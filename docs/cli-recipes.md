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
ignore_globs = ["fixtures/*", "tmp/*"]
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
