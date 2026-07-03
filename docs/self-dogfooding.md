# Self-Dogfooding

v0.7 is the self-dogfooding release. The goal is to show that
`repo-sentinel-lite` is used as a portfolio hygiene gate, not only as an
isolated scanner demo.

Self-dogfooding evidence should stay boring and auditable:

- record the target repository
- record the integration entry point
- record whether `.reposentinel.toml` is present
- record whether `.reposentinel-baseline.json` is present
- record the gate command used for local or CI validation
- record any remaining baseline drift follow-up

## Adoption Matrix

| Repository | Configuration strategy | Baseline present? | Why paths are ignored | Command |
| --- | --- | --- | --- | --- |
| `sec-writeups-public` | Project-specific `.reposentinel.toml` plus a reviewed suppression baseline | Yes: `.reposentinel-baseline.json` | Generated reports are derived output; ignoring them avoids scanning duplicate evidence while authored material remains reviewable. | `repo-sentinel scan --baseline .reposentinel-baseline.json --fail-on-severity error --format text .` |
| `LogLens` | Filename and repository hygiene only; high-entropy content scanning is disabled | No: the first reviewed run passed without one | C++ build trees, binaries, CMake metadata, and generated reports are local or reproducible output outside the narrow hygiene gate. | `repo-sentinel scan --fail-on-severity error --format text .` |
| `telemetry-lab` | Filename and high-entropy scanning at a reviewed `4.5` threshold; CI pins production `repo-sentinel-lite==0.6.3` | No: the reviewed source tree passed without one | Processed data, demo artifacts, and regeneration scratch paths are reproducible; source, configs, and raw sample inputs remain in scope. | `repo-sentinel scan --fail-on-severity error --format text .` |

## sec-writeups-public

Observed on 2026-06-29:

- repository: `stacknil/sec-writeups-public`
- remote evidence: `.reposentinel.toml` and `.reposentinel-baseline.json` are
  tracked on `origin/main`
- config evidence: `.reposentinel.toml` contains project-specific ignores for
  generated report files
- baseline evidence: `.reposentinel-baseline.json` exists as a committed
  suppression baseline

This is a good adoption signal: the repository has moved past an ad hoc local
scan and now has explicit repo-sentinel configuration plus a reviewable
baseline artifact.

It is not yet enough to claim ongoing green status. The current follow-up is to
review latest baseline drift on `sec-writeups-public/main`, refresh the
baseline only after review, and confirm the gate command below returns no
unsuppressed `error` findings:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --fail-on-severity error \
  --format text \
  .
```

When the drift review is complete, update this file with:

- the commit or PR that refreshed the baseline
- whether the gate runs locally, in CI, or both
- whether `.reposentinel.toml` ignores remain narrow and justified
- whether future baselines are generated with redaction defaults

## LogLens

Observed on 2026-06-29:

- repository: `stacknil/LogLens`
- integration evidence: PR #74 merged `.github/workflows/repo-sentinel.yml`
  as a `Repo Sentinel` GitHub Actions gate
- config evidence: `.reposentinel.toml` contains C++ build and output ignores
  for `build/**`, `build_manual*`, `out/**`, generated reports, `*.exe`, and
  CMake metadata
- gate command: `repo-sentinel scan --fail-on-severity error --format text .`
- baseline evidence: no `.reposentinel-baseline.json` was added; the first
  reviewed run passed without a baseline
- scope: LogLens uses this gate for repository hygiene and accidental sensitive
  filenames only

LogLens intentionally disables high-entropy content scanning in this
integration:

```toml
max_text_file_size = 0
entropy_threshold = 999.0
```

That scope keeps fixture logs and C++ build artifacts out of the gate while
still checking for missing standard files and suspicious filenames.

The workflow installs `repo-sentinel-lite` from production PyPI under Python 3.14
because the currently published package metadata still requires Python 3.14.
After the next production release publishes the Python 3.11+ metadata, LogLens
should move this workflow back to the normal supported Python policy. This is
release-hardening follow-up, not a blocker for the narrow LogLens hygiene gate.

## telemetry-lab

Observed on 2026-06-30:

- repository: `stacknil/telemetry-lab`
- integration evidence: PR #71 merged `.github/workflows/repo-sentinel.yml`
  as a `Repo Sentinel` GitHub Actions gate
- package evidence: the workflow installs `repo-sentinel-lite==0.6.3` from
  production PyPI under Python 3.14
- gate command: `repo-sentinel scan --fail-on-severity error --format text .`
- baseline evidence: no `.reposentinel-baseline.json` was added; the reviewed
  source tree passed without suppressions
- generated-output ignores: `data/processed/**`, `demos/*/artifacts/**`,
  `.artifact-regeneration-tmp/**`, and `.pytest-artifacts*/**`
- in-scope evidence: `src/**`, `configs/**`, `demos/*/config/**`, `data/raw/**`,
  and `demos/*/data/raw/**` remain scanned

The default entropy threshold produced 137 redacted false positives from long
identifiers and schema vocabulary. The integration uses a reviewed threshold
of `4.5` instead of checking in a noise-heavy baseline. A deterministic
6-bit-entropy probe still produced a finding at that threshold, while the real
repository scan returned `No findings`.

Local validation also passed 177 tests and confirmed that 23 strict artifacts
matched regenerated output while 6 visual snapshots regenerated successfully.
The GitHub Actions `CI` and `Repo Sentinel` checks passed before merge.

## Review Expectations

Dogfooding repositories should not silently broaden scan exclusions or add
baseline entries without explanation. Treat these files as security-adjacent:

- `.reposentinel.toml`
- `.reposentinel-baseline.json`
- `.pre-commit-config.yaml`
- CI workflow files that run `repo-sentinel`

For baseline review rules, see [`baseline-review.md`](baseline-review.md).
For pre-commit and CI setup, see
[`pre-commit-integration.md`](pre-commit-integration.md).
For scanner boundaries, see [`threat-model.md`](threat-model.md).
