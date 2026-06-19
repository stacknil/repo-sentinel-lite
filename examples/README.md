# Examples

These fixtures show the same repository hygiene workflow from two angles:

- `dirty-repo` contains synthetic findings a reviewer may fix or baseline.
- `clean-repo` contains the standard files expected by the default scanner
  rules.

The checked-in outputs under `examples/outputs/` are static review fixtures.
They demonstrate scanner output, baseline output, and fail-on-findings behavior
without requiring a reviewer to infer the CLI contract from tests alone.

## Dirty Repository

Run a JSON scan:

```bash
repo-sentinel scan --format json examples/dirty-repo
```

Expected output:

```text
examples/outputs/dirty-scan.json
```

Write a baseline:

```bash
repo-sentinel scan --write-baseline baseline.json examples/dirty-repo
```

Expected baseline shape:

```text
examples/outputs/dirty-baseline.json
```

Fail when unsuppressed findings remain:

```bash
repo-sentinel scan --format text --fail-on-findings examples/dirty-repo
```

Expected output and exit behavior:

```text
examples/outputs/dirty-fail-on-findings.txt
exit code: 1
```

## Clean Repository

Run a JSON scan:

```bash
repo-sentinel scan --format json examples/clean-repo
```

Expected output:

```text
examples/outputs/clean-scan.json
```

Write a baseline:

```bash
repo-sentinel scan --write-baseline baseline.json examples/clean-repo
```

Expected baseline shape:

```text
examples/outputs/clean-baseline.json
```

Fail when unsuppressed findings remain:

```bash
repo-sentinel scan --format text --fail-on-findings examples/clean-repo
```

Expected output and exit behavior:

```text
examples/outputs/clean-fail-on-findings.txt
exit code: 0
```

