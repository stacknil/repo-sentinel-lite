# Output Format Stability

`repo-sentinel-lite` is designed to produce reviewer-friendly outputs that can
be saved by CI, but each format has a different stability contract.

## Text Output

Text output is for humans and CI logs:

```bash
repo-sentinel scan --format text --fail-on-severity error .
```

For the same repository tree, configuration, baseline, and package version,
the text summary is stable enough to save as a CI log or artifact. Treat it as
review evidence, not as a machine API. Prefer JSON when another tool will parse
the result.

High-entropy tokens are redacted by default. Use `--reveal-secrets` only for a
local, intentional investigation, and do not upload revealed output as a CI
artifact.

## JSON Scan Output

JSON scan output is the preferred machine-readable CI artifact:

```bash
repo-sentinel scan --format json --output repo-sentinel-report.json .
```

For the same repository tree, configuration, baseline, and package version, the
JSON report uses sorted findings and deterministic fingerprints. It is suitable
for CI artifacts, reviewer attachments, and local diffing.

A clean JSON report means no unsuppressed findings matched the configured
heuristics. It does not prove that the repository contains no leaked secret or
credential.

## Baseline Output

Baseline output is a review artifact:

```bash
repo-sentinel scan --write-baseline .reposentinel-baseline.json .
```

Baseline findings are sorted and high-entropy tokens are redacted by default.
The `generated_at` field changes whenever a new baseline is written, so a
freshly generated baseline is not expected to be byte-for-byte identical across
runs. Review the finding entries and fingerprints, not only the timestamp.

When reviewing drift, write a candidate file and compare it before replacing
the committed baseline:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --update-baseline .reposentinel-baseline.next.json \
  .
```

Do not treat a baseline as proof that findings are safe. A baseline suppresses
reviewed findings so new drift remains visible.
