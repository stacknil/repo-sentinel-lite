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
