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
- Adds `repo-sentinel baseline audit` with `active`, `stale`, `ambiguous`, and
  `unmatched` classifications.
- Adds `.reposentinel.toml` allowlist support for paths, rules, token hashes,
  and scoped inline comments.
- Adds `scan --changed-files` for integrations that already know the changed
  file list.
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

## Boundary

`repo-sentinel-lite` remains heuristic. A clean scan does not prove that a
repository has no leaked credential.

This release does not replace enterprise secret scanning, credential inventory,
revocation, or Git history scanning.
