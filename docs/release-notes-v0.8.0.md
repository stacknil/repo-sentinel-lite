# v0.8.0 Release Notes

Theme: Rule and Baseline Semantics Release.

## What Changed

- Splits the scanner implementation into focused modules for configuration,
  traversal, rules, baseline handling, report formatting, SARIF, and redaction.
- Adds semantic finding fields: `rule_id`, `rule_version`, `severity`,
  `fingerprint`, `evidence`, and `remediation_hint`.
- Adds structured heuristic detectors for PEM private-key headers,
  GitHub-token-like prefixes, AWS access-key-like prefixes, and generic
  secret-adjacent assignment contexts.
- Adds `repo-sentinel baseline audit` with `active`, `relocated`, `changed`,
  `stale`, `ambiguous`, and `unmatched` classifications. Content identity is
  based on `rule_id`, path, and token SHA-256; location identity adds the line
  only for audit classification, so file-header insertions are not stale drift.
- Adds `.reposentinel.toml` allowlist support for paths, rules, token hashes,
  and scoped inline comments.
- Adds `scan --changed-files` for integrations that already know the changed
  file list.
- Rejects fingerprint collisions instead of silently dropping a distinct
  finding during report or baseline normalization.
- Adds the initial remote pull-request gate: changed-file errors block,
  changed-file warnings and skipped coverage entries report, and baseline
  drift is emitted by a separate non-blocking audit job.
- Updates package metadata to describe the project as repository hygiene and
  lightweight secret-adjacent scanning, not a broad secret-scanning guarantee.

## Compatibility Notes

- `kind` remains present for existing JSON and baseline consumers.
- Baseline `schema_version` remains `1`; v0.8 adds optional semantic fields
  rather than invalidating existing baselines.
- The built-in pre-commit provider continues scanning the repository root.
  Changed-files mode is explicit opt-in.
- Assignment-context findings intentionally do not duplicate high-entropy
  findings for the same token value.
- Assignment-context findings skip obvious source-code expression values such
  as function calls and object dereferences while still flagging literal
  configuration-style assignments.

## Boundary

`repo-sentinel-lite` remains heuristic. A clean scan does not prove that a
repository has no leaked credential.

This release does not replace enterprise secret scanning, credential inventory,
revocation, or Git history scanning.
