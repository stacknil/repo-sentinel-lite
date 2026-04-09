# Production PyPI Go / No-Go Decision

## Executive Summary

`repo-sentinel-lite` is **not** ready for an immediate production PyPI publish
 today, but it is close. The repository has strong evidence that its packaging
 and GitHub Actions release flow work end to end because the real TestPyPI
 smoke release for `0.6.2rc1` succeeded via GitHub Releases, GitHub Actions,
 Trusted Publishing, and a clean install from TestPyPI.

The remaining gaps are production-specific rather than structural:

- production PyPI Trusted Publisher configuration cannot be confirmed from the
  repository alone
- the production project `repo-sentinel-lite` does not currently exist on
  production PyPI
- the first stable release still requires explicit maintainer action to push,
  tag, and publish from the prepared repository state

## Final Classification

**GO AFTER MINIMAL PREP**

## Decision Criteria

### Criteria used

- successful real TestPyPI smoke evidence
- release workflow confidence
- package metadata and README suitability for PyPI
- clean stable target version choice
- production Trusted Publisher readiness
- production project-name / first-project-creation confidence
- residual operational risk for a first production publish

### Decision outcome by criterion

| Criterion | Assessment | Notes |
| --- | --- | --- |
| Real TestPyPI smoke | Pass | `v0.6.2rc1` release workflow succeeded and the package installed from TestPyPI |
| Workflow shape | Pass in principle | Separate build and publish jobs, `id-token: write`, non-reusable publish path |
| Production workflow targeting | Prepared in repo | GitHub prereleases now route to TestPyPI and stable releases route to PyPI |
| Package metadata | Acceptable | Name, version, README, license, URLs, Python requirement, and console script are present |
| README / long description | Acceptable with minor follow-up | `twine check` passed; install instructions should be updated after a successful production publish |
| Stable version candidate | Prepared | Repository metadata is now aligned to `0.6.2` |
| Production Trusted Publisher | Unknown, needs manual confirmation | Cannot be proven locally; current repo only shows TestPyPI environment/config alignment |
| Production package-name risk | Manageable but real | Production project does not appear to exist yet, so first publish likely needs the pending/new publisher path |

## Evidence From the Successful TestPyPI Smoke

- GitHub prerelease: `v0.6.2rc1`
- Release workflow run: `24128896893`
- Build job: succeeded
- Publish-to-TestPyPI job: succeeded
- TestPyPI package page:
  `https://test.pypi.org/project/repo-sentinel-lite/0.6.2rc1/`
- Clean install verification from TestPyPI succeeded for:
  - `repo-sentinel --help`
  - `python -m repo_sentinel --help`

This is strong evidence that the package builds correctly, uploads correctly via
 OIDC-based publishing, and installs cleanly for users. It is not, by itself,
 evidence that production PyPI Trusted Publisher configuration already exists.

## Assessment of Workflow Readiness

The current workflow in
[`release.yml`](D:/OneDrive/Code/repo-sentinel-lite/.github/workflows/release.yml)
is production-compatible **in shape**:

- it builds distributions in one job and publishes in a separate job
- the publishing job has `permissions: id-token: write`
- the publish step is in a normal workflow job, not a reusable workflow trap
- the release job verifies that the tag version matches both package version
  fields before building

The workflow is now prepared for both publish targets while preserving the
safe release shape:

- GitHub prereleases publish to TestPyPI through the `testpypi` environment
- stable GitHub releases publish to PyPI through the `pypi` environment

That removes the main repository-side workflow gap. The remaining blockers are
manual GitHub/PyPI-side confirmations rather than additional repo refactoring.

## Assessment of Trusted Publisher Readiness

### What is known

- GitHub-side TestPyPI release automation works
- the repository has a `testpypi` environment in GitHub
- the repository does not yet have a `pypi` environment in GitHub
- Trusted Publishing to TestPyPI has already succeeded

### What is inferred

- the team understands the Trusted Publishing setup well enough to configure a
  production publisher cleanly
- the repository-side workflow path is now prepared for a first stable publish

### What still requires manual verification

- whether production PyPI already has a matching Trusted Publisher configured
- if configured, whether the production publisher matches:
  - GitHub owner `stacknil`
  - repository `repo-sentinel-lite`
  - workflow file `.github/workflows/release.yml`
  - any chosen production environment name
- if not configured, whether the first production publish will use:
  - a pending publisher path
  - or a newly created publisher on first successful use

Because this cannot be proven from the repo alone, this remains a real blocker
 to `GO NOW`.

## Assessment of Package Name / Project Creation Risk

The production project name `repo-sentinel-lite` does **not** appear to be a
live production PyPI project:

- `https://pypi.org/pypi/repo-sentinel-lite/json` returned `404`
- `https://pypi.org/simple/repo-sentinel-lite/` returned `404`
- `https://pypi.org/simple/repo_sentinel_lite/` returned `404`

That is good news in one sense: there is no visible existing production package
 colliding with the expected project metadata. It also means the first
 production publish likely has to create the project through the pending/new
 publisher flow, and that publisher setup should be verified before release day.

Because pending publishers do not reserve names before first publish, there is
still a small operational timing risk until the first production publish lands.

## Package Metadata and README Assessment

Package metadata in
[`pyproject.toml`](D:/OneDrive/Code/repo-sentinel-lite/pyproject.toml) looks
acceptable for a first production release:

- project name present
- version present
- README configured as long description
- MIT license declared and `LICENSE` included
- Python requirement declared as `>=3.14`
- repository URLs are present
- console script entry point is present
- repository version metadata is now prepared at `0.6.2`

The README in [README.md](D:/OneDrive/Code/repo-sentinel-lite/README.md) is
PyPI-friendly enough for a first release:

- short description is clear
- usage examples are compact
- long description rendered cleanly enough for `twine check` to pass

Minor caveat:

- the install example still points to an older GitHub tag and explicitly says
  production PyPI is not available yet

That wording is correct today, but it should be updated after a successful
 production publish.

## Recommended Next Stable Version

**Recommended next stable version: `0.6.2`**

Why:

- the successful smoke was `0.6.2rc1`
- no evidence suggests a structural issue that requires skipping to `0.6.3`
- promoting from `0.6.2rc1` to `0.6.2` is the cleanest first production target

## Top Remaining Risks

1. Production Trusted Publisher status is still unverified manually.
2. The `pypi` GitHub environment still needs to be created or confirmed to
   match the PyPI configuration.
3. The production project does not exist yet, so the first publish is also a
   project-creation event.
4. The README install section will be stale immediately after production publish
   unless updated as part of the release wrap-up.

## Clear Final Recommendation

Proceed toward a first production PyPI release **only after minimal prep**:

1. confirm or create the production PyPI Trusted Publisher configuration
2. create or confirm the `pypi` GitHub environment so it matches the PyPI
   configuration exactly
3. run the normal preflight checks against the prepared `0.6.2` metadata
4. publish the first stable production release and verify install

This repository is close enough that a production release looks reasonable, but
the remaining gaps are real enough that calling it `GO NOW` would be too
optimistic.
