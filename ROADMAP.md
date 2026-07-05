# Roadmap

`repo-sentinel-lite` is in a rule and baseline semantics phase. The near-term
focus is to keep the scanner lightweight while making each finding easier to
review, baseline, audit, and suppress narrowly.

## v0.8 Focus

- Keep rules heuristic, explicit, and redaction-safe.
- Prefer structured rule semantics over further entropy-threshold tuning.
- Keep baseline compatibility while adding audit classifications.
- Make allowlists narrow and reviewable: path, rule, token hash, or scoped
  comment.
- Keep pre-commit defaults broad; use changed-files mode only when the caller
  intentionally provides a file list.

## External Review Surface

Open review issues should be sparse and reproducible from committed synthetic
fixtures. A useful issue names the sample input, expected JSON or text output,
and acceptance criteria for a bounded scanner, fixture, or documentation
change.

The current public review entry is intentionally narrow: trace one synthetic
dirty-repository finding to the redacted JSON/text output and confirm the
reviewer-facing evidence path is understandable.

## Parked Directions

- Clean-environment consumer setup feedback, only when it includes exact
  install and scan commands plus a reproducible mismatch.
- Additional synthetic hygiene fixtures, only when the expected JSON output and
  focused test are known before implementation.
- Suppression or threshold examples, only when they use fake repository
  context and explain why the exception is narrower than disabling a check.
- Additional provider-specific token rules, only when they are prefix or
  format heuristics with clear non-claims.
- Keep examples public-safe; no real secrets, private repository metadata,
  local paths, or raw credentials.
