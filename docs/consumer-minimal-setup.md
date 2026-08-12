# Consumer Minimal Setup

Use this when a repository only needs a small, auditable hygiene gate.

## Install

Use Python 3.11 or newer:

```bash
python -m pip install repo-sentinel-lite
```

## First Scan

Run a scan from the repository root:

```bash
repo-sentinel scan .
```

Run the error-level gate when the command should fail CI or a local check on
unsuppressed error findings:

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
    rev: v0.8.0
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

## Optional CI

For a simple GitHub Actions gate, add `.github/workflows/repo-sentinel.yml` to
the consumer repository:

```yaml
name: Repo Sentinel

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  repo-sentinel:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"
      - run: python -m pip install repo-sentinel-lite==0.8.0
      - name: Scan changed files
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        shell: bash
        run: |
          mapfile -d '' changed_files < <(
            git diff --name-only --diff-filter=ACMR -z "$BASE_SHA" "$HEAD_SHA"
          )
          if ((${#changed_files[@]} == 0)); then
            exit 0
          fi
          repo-sentinel scan \
            --changed-files \
            --fail-on-severity error \
            --format text \
            . \
            -- \
            "${changed_files[@]}"
```

This template keeps the remote gate focused on changed files. Warnings and
coverage skips are reported without blocking; run `repo-sentinel baseline
audit` in a separate non-blocking job when the consumer has a baseline. Add
`.reposentinel.toml` only for consumer-specific generated paths, and keep
source, configuration, sample inputs, and authored documentation in scope.

When CI should preserve outputs for review, see
[`output-format-stability.md`](output-format-stability.md).
