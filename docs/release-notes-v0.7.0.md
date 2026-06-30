# v0.7.0 Release Notes

Adoption release for portfolio-level repository hygiene enforcement.

## Adoption Evidence

- Records self-dogfooding evidence for `sec-writeups-public`, `LogLens`, and
  `telemetry-lab`, including each repository's configuration strategy,
  baseline status, and ignore-path rationale.
- Adds before-and-after example repositories plus checked scan, baseline, and
  fail-on-findings outputs under `examples/`.
- Adds reviewer-facing guides for baseline review, pre-commit integration, and
  threat-model boundaries.
- Keeps redaction and baseline behavior visible in public docs instead of
  treating them as implicit scanner details.

## Package And Release Posture

- Widens package metadata to Python 3.11 and newer.
- Validates CI across Python 3.11, 3.12, 3.13, and 3.14 on Ubuntu and Windows.
- Keeps release automation guarded so GitHub release tags must match both
  `pyproject.toml` and `src/repo_sentinel/__init__.py` before a package build
  can publish.
- Updates the pre-commit provider examples to pin `rev: v0.7.0`.

## Scanner Behavior Since 0.6.3

- Adds `--no-default-baseline` for scans that need to ignore a repository-root
  `.reposentinel-baseline.json` during review.
- Supports recursive child-directory ignore globs such as `fixtures/**`.
- Streams scanner traversal and avoids unnecessary broad walks for required
  file checks.
- Hardens default output and baseline redaction paths while preserving the
  lightweight local scanning model.

## Compatibility And Migration

- Requires Python 3.11 or newer.
- No baseline schema migration is required.
- Consumers using pre-commit should update the provider `rev` to `v0.7.0`
  after the release is published.

## Boundaries

`repo-sentinel-lite` remains a lightweight hygiene gate. A clean scan does not
prove that a repository has no leaked credentials, and this release does not
replace enterprise secret scanning or semantic security analysis.
