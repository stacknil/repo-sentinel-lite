# Roadmap

`repo-sentinel-lite` is in a stabilization phase. The near-term focus is to
keep review paths, tests, documentation boundaries, and release evidence stable
rather than expand project count or scanner scope.

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
- Keep examples public-safe; no real secrets, private repository metadata,
  local paths, or raw credentials.
