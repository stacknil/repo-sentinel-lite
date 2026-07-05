# CLI Recipes

These examples assume you are running from the repository root.

## Local text scan

```bash
repo-sentinel scan --format text .
```

## JSON output to file

```bash
repo-sentinel scan --output reports/repo-sentinel.json .
```

High-entropy tokens are redacted by default in CLI output and generated
baselines. To inspect full token values locally:

```bash
repo-sentinel scan --reveal-secrets .
```

## Fail on severity in CI

Fail only when `error` findings remain:

```bash
repo-sentinel scan --fail-on-severity error .
```

Fail when any `warning` or `error` finding remains:

```bash
repo-sentinel scan --fail-on-severity warning .
```

## Write a baseline

```bash
repo-sentinel scan --write-baseline baselines/repo-sentinel-baseline.json .
```

For baseline review expectations, redaction behavior, and a synthetic example,
see [`baseline-review.md`](baseline-review.md).

## Update a baseline

Write a refreshed canonical baseline for the current findings state:

```bash
repo-sentinel scan --update-baseline baselines/repo-sentinel-baseline.json .
```

Refresh from an existing suppression baseline:

```bash
repo-sentinel scan \
  --baseline baselines/repo-sentinel-baseline.json \
  --update-baseline baselines/repo-sentinel-baseline.next.json \
  .
```

Audit the committed baseline without writing a replacement file:

```bash
repo-sentinel baseline audit --baseline baselines/repo-sentinel-baseline.json .
```

## Run with baseline suppression

```bash
repo-sentinel scan --baseline baselines/repo-sentinel-baseline.json .
```

## Ignore generated paths

Common generated and dependency directories such as `.venv`, `venv`,
`.venv-*`, `node_modules`, `dist`, `dist-*`, `build`, `.tox`, `.nox`,
`.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `*.egg-info`, `coverage`,
`htmlcov`, and `__pycache__` are ignored by default. Add project-specific
ignores with `.reposentinel.toml`:

```toml
ignore_globs = ["fixtures/**", "tmp/**"]
```

Child-glob patterns such as `fixtures/*`, `fixtures/**`, and `fixtures/**/*`
prune the matching directory during traversal.

Use narrow allowlists when a fixture should not be emitted as a finding:

```toml
[allowlist]
paths = ["fixtures/**"]
rules = ["repo.suspicious_filename"]
token_hashes = ["sha256:3eb1bd439947"]
```

## Adjust large-file scanning

Text files larger than `max_text_file_size` bytes are skipped for high-entropy
content scanning. Raise the limit for repositories that need larger text files
included:

```toml
max_text_file_size = 2097152
```

## Run with the default committed baseline

If `.reposentinel-baseline.json` exists in the repository root, it is applied
automatically:

```bash
repo-sentinel scan .
```

Temporarily ignore the repository-root default baseline and show all current
findings:

```bash
repo-sentinel scan --no-default-baseline .
```

## Prune stale baseline entries

```bash
repo-sentinel scan \
  --baseline baselines/repo-sentinel-baseline.json \
  --prune-baseline baselines/repo-sentinel-baseline.pruned.json \
  .
```

## Generate SARIF to file

```bash
repo-sentinel scan --format sarif --output reports/repo-sentinel.sarif .
```

## Scan changed files

Use this only when the caller already has a trusted changed-file list:

```bash
repo-sentinel scan --changed-files . src/app.py docs/example.md
```
