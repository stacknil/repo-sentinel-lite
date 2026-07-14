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

In v0.8 and newer, each entry in `findings` includes:

- `rule_id`: stable rule identifier such as `secret.high_entropy`
- `rule_version`: rule semantics version for audit context
- `severity`: `warning` or `error`
- `fingerprint`: deterministic finding identity for baselines
- `evidence`: structured, redaction-safe evidence for the finding
- `remediation_hint`: concise review guidance

Treat `rule_id`, `rule_version`, `severity`, `fingerprint`, and redacted
`evidence` as the CI artifact contract. The compatibility sections
`high_entropy_findings`, `missing_files`, and `suspicious_files` remain present
for older consumers, but new integrations should prefer `findings`.

### Scan coverage diagnostics

When at least one discovered file cannot be content-inspected, the JSON report
adds a `coverage` object:

```json
{
  "coverage": {
    "files_considered": 3,
    "files_inspected": 1,
    "files_skipped": 2,
    "skipped_by_reason": {
      "binary": 1,
      "oversize": 1
    },
    "skipped_files": [
      {"path": "assets/example.bin", "reason": "binary"},
      {"path": "generated/large.txt", "reason": "oversize"}
    ]
  }
}
```

Paths are normalized repository-relative paths. Entries are sorted, reason
counts use a fixed low-cardinality vocabulary, and diagnostics contain no file
content, raw token, operating-system error, or repository-root path. Supported
reasons are:

- `binary`: the sampled bytes fail the text heuristic
- `oversize`: file size exceeds `max_text_file_size`
- `symlink_policy`: the filename is inspected for hygiene, but target content
  is not followed
- `unreadable`: metadata or bytes could not be read
- `unsupported_encoding`: bytes pass the text heuristic but cannot be decoded
  as UTF-8, UTF-16, or CP1252

When traversal prunes one or more directory symlinks, `coverage` additionally
contains `directories_skipped` and a sorted `skipped_directories` list. These
fields are omitted when no directory link is skipped, preserving the existing
file-only shape. `files_considered`, `files_skipped`, `skipped_files`, and
`skipped_by_reason` continue to describe files only.

The previous permissive Latin-1 fallback is intentionally not used because it
would make `unsupported_encoding` unreachable and could classify arbitrary
bytes as text.

Coverage diagnostics are informational. `--fail-on-findings` and
`--fail-on-severity` continue to evaluate security findings only; baselines
neither suppress nor remove coverage. Text output appends a coverage section,
and SARIF places the same object in
`runs[0].properties.repoSentinelCoverage` instead of emitting false-positive
security results.

Compatibility impact is additive and conditional: reports with no skipped
discovered files retain their prior shape, while reports with skipped files
gain `coverage` (plus the text or SARIF projection). Strict-schema consumers
should allow this optional field. Its absence does not claim complete
repository coverage: ignored paths and a `--changed-files` selection remain
outside the considered-file count.

See the [symlink policy](symlink-policy.md) for the full-scan and changed-file
containment matrix.

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

For drift review without rewriting a candidate file, use:

```bash
repo-sentinel baseline audit --format json --baseline .reposentinel-baseline.json .
```

The JSON audit groups findings into `active`, `stale`, `ambiguous`, and
`unmatched`. It is suitable as a CI artifact when teams want reviewer evidence
without automatically changing a committed baseline.
