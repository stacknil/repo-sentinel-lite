# Self-Dogfooding

v0.7 is the self-dogfooding release. The goal is to show that
`repo-sentinel-lite` is used as a portfolio hygiene gate, not only as an
isolated scanner demo.

Self-dogfooding evidence should stay boring and auditable:

- record the target repository
- record the integration entry point
- record whether `.reposentinel.toml` is present
- record whether `.reposentinel-baseline.json` is present
- record the gate command used for local or CI validation
- record any remaining baseline drift follow-up

## Status

| Repository | Status | Evidence | Next action |
| --- | --- | --- | --- |
| `sec-writeups-public` | Bootstrapped | `.reposentinel.toml` and `.reposentinel-baseline.json` are tracked on `origin/main` | Review latest baseline drift and converge the gate back to a clean run |
| `LogLens` | Pending | No integration evidence recorded here yet | Add a small local or CI hygiene gate |
| `telemetry-lab` | Pending | No integration evidence recorded here yet | Add a small local or CI hygiene gate |

## sec-writeups-public

Observed on 2026-06-29:

- repository: `stacknil/sec-writeups-public`
- remote evidence: `.reposentinel.toml` and `.reposentinel-baseline.json` are
  tracked on `origin/main`
- config evidence: `.reposentinel.toml` contains project-specific ignores for
  generated report files
- baseline evidence: `.reposentinel-baseline.json` exists as a committed
  suppression baseline

This is a good adoption signal: the repository has moved past an ad hoc local
scan and now has explicit repo-sentinel configuration plus a reviewable
baseline artifact.

It is not yet enough to claim ongoing green status. The current follow-up is to
review latest baseline drift on `sec-writeups-public/main`, refresh the
baseline only after review, and confirm the gate command below returns no
unsuppressed `error` findings:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --fail-on-severity error \
  --format text \
  .
```

When the drift review is complete, update this file with:

- the commit or PR that refreshed the baseline
- whether the gate runs locally, in CI, or both
- whether `.reposentinel.toml` ignores remain narrow and justified
- whether future baselines are generated with redaction defaults

## Review Expectations

Dogfooding repositories should not silently broaden scan exclusions or add
baseline entries without explanation. Treat these files as security-adjacent:

- `.reposentinel.toml`
- `.reposentinel-baseline.json`
- `.pre-commit-config.yaml`
- CI workflow files that run `repo-sentinel`

For baseline review rules, see [`baseline-review.md`](baseline-review.md).
For pre-commit and CI setup, see
[`pre-commit-integration.md`](pre-commit-integration.md).
For scanner boundaries, see [`threat-model.md`](threat-model.md).

