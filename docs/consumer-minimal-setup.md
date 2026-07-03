# Consumer Minimal Setup

Use this when a repository only needs a small, auditable hygiene gate.

## Install

Use Python 3.11 or newer:

```bash
python -m pip install repo-sentinel-lite
```

## First Scan

Run the error-level gate from the repository root:

```bash
repo-sentinel scan --fail-on-severity error --format text .
```

If the output is `No findings.`, the repository is clean for the default
error-level gate. Warning-level findings, such as missing standard files, can
still be reviewed with:

```bash
repo-sentinel scan --fail-on-severity warning --format text .
```

## Optional Config

Add `.reposentinel.toml` only for intentional generated paths or project
fixtures:

```toml
ignore_globs = ["dist/**", "generated/**"]
```

Keep ignores narrow. Source files, configuration, sample inputs, and authored
documentation should usually remain in scope.

## Optional Baseline

Create a baseline only after reviewing current findings:

```bash
repo-sentinel scan --no-default-baseline --format text .
repo-sentinel scan --write-baseline .reposentinel-baseline.json .
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --fail-on-severity error \
  --format text \
  .
```

Review baseline drift before committing updates:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --update-baseline .reposentinel-baseline.next.json \
  .
```

For review rules, see [`baseline-review.md`](baseline-review.md).

## Optional Pre-Commit

Pin the provider by release tag:

```yaml
repos:
  - repo: https://github.com/stacknil/repo-sentinel-lite
    rev: v0.7.1
    hooks:
      - id: repo-sentinel-error
```

Run it manually:

```bash
python -m pip install pre-commit
pre-commit run repo-sentinel-error --hook-stage manual --all-files
```

For the fuller pre-commit and CI guide, see
[`pre-commit-integration.md`](pre-commit-integration.md).
