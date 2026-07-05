# Pre-Commit Integration Guide

Use the pre-commit provider when a repository should fail locally before
review, and reuse the same gate in CI when the repository needs a repeatable
server-side check.

The provider manifest is [`../.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml).
It exposes two hooks:

- `repo-sentinel-error`: fails when unsuppressed `error` findings remain
- `repo-sentinel-warning`: fails when unsuppressed `warning` or `error`
  findings remain
- `repo-sentinel-error-changed`: opt-in changed-files variant for `error`
  findings
- `repo-sentinel-warning-changed`: opt-in changed-files variant for
  `warning` or `error` findings

## Install

Install `pre-commit` in the repository where you want the gate:

```bash
python -m pip install pre-commit
```

Install the CLI as well when you want to run scans directly while reviewing a
baseline or debugging a finding:

```bash
python -m pip install repo-sentinel-lite
```

Pre-commit installs the hook package from the pinned provider `rev`, so a
consumer repository does not need a separate `repo-sentinel-lite` dependency
just for hook execution.

## Configure

Add `.pre-commit-config.yaml` to the consumer repository:

```yaml
repos:
  - repo: https://github.com/stacknil/repo-sentinel-lite
    rev: v0.7.1
    hooks:
      - id: repo-sentinel-error
```

Use `repo-sentinel-warning` when the repository is ready to fail on missing
standard files as well as suspicious files and high-entropy findings:

```yaml
repos:
  - repo: https://github.com/stacknil/repo-sentinel-lite
    rev: v0.7.1
    hooks:
      - id: repo-sentinel-warning
```

Install the local hooks:

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

Run the hook manually:

```bash
pre-commit run repo-sentinel-error --hook-stage manual --all-files
```

The provider hooks set `pass_filenames: false` and scan the repository root.
Configure project-specific ignores in `.reposentinel.toml` rather than passing
file lists from pre-commit:

```toml
ignore_globs = ["fixtures/**", "generated/**"]
```

For advanced local hooks that manage their own file list, v0.8 adds explicit
changed-files hooks:

```yaml
repos:
  - repo: https://github.com/stacknil/repo-sentinel-lite
    rev: v0.7.1
    hooks:
      - id: repo-sentinel-error-changed
```

The same mode is available directly:

```bash
repo-sentinel scan --changed-files . src/app.py docs/example.md
```

This mode scans only the listed files for file and token rules while still
checking repository-level required files. The built-in provider keeps the
root-scan behavior so existing consumers do not lose coverage by upgrading.

## Trigger a Failure

Use the checked dirty example when you want to see the failure contract without
modifying a consumer repository:

```bash
repo-sentinel scan --fail-on-severity error examples/dirty-repo
```

In a consumer repository, a suspicious file will make the hook fail:

```bash
printf "PLACEHOLDER=1\n" > .env
pre-commit run repo-sentinel-error --hook-stage manual --all-files
rm .env
```

Do not commit the temporary `.env` file. If the hook fails on a real file,
prefer fixing or removing the finding before creating a baseline.

## Create a Baseline

Create a baseline only after the first scan has been reviewed:

```bash
repo-sentinel scan --no-default-baseline --format text .
repo-sentinel scan --write-baseline .reposentinel-baseline.json .
```

Confirm the baseline suppresses the accepted findings:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --fail-on-severity error \
  .
```

The provider hook automatically applies `.reposentinel-baseline.json` when it
is present in the repository root.

## Review a Baseline

Review `.reposentinel-baseline.json` like a security-adjacent change:

- confirm every new finding family is expected
- confirm high-entropy values remain redacted
- explain why a suspicious file or missing required file is acceptable
- remove stale entries when the underlying finding has been fixed

To review drift, write a candidate baseline and diff it before replacing the
committed file:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --update-baseline .reposentinel-baseline.next.json \
  .
```

When you need classification rather than a rewritten candidate, run:

```bash
repo-sentinel baseline audit --baseline .reposentinel-baseline.json .
```

For the full baseline review model, see
[`baseline-review.md`](baseline-review.md).

## Reuse in CI

CI can reuse the pre-commit hook so local and server-side behavior stay aligned:

```yaml
name: repo-sentinel

on:
  pull_request:
  push:

jobs:
  repo-sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.11"
      - run: python -m pip install pre-commit
      - run: pre-commit run repo-sentinel-error --hook-stage manual --all-files
```

For simpler CI jobs that do not need pre-commit, install the package and run the
same severity gate directly:

```bash
python -m pip install repo-sentinel-lite
repo-sentinel scan --fail-on-severity error .
```

