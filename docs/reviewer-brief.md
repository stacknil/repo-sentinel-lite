# Reviewer brief

## Problem

Small repositories still need basic hygiene checks, secret-adjacent scanning, and reviewer-visible baselines, but many teams do not need or want a heavyweight platform just to catch obvious problems.

## What it does

`repo-sentinel-lite` is a deterministic Python CLI that scans a repository for:

- suspicious filenames such as `.env`, `*.pem`, and `id_rsa`
- high-entropy strings that may look like secrets
- structured secret-adjacent patterns such as PEM private-key headers,
  provider-prefix token shapes, and assignment contexts
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It supports `.reposentinel.toml` config, narrow allowlists, JSON baselines,
baseline audit output, redacted output by default, changed-files scans, and
pre-commit integration.

## Reviewer Evidence

- Reproducible command: `repo-sentinel scan --format json .`
- Deterministic outputs: stable JSON findings, text summaries, and baseline files with redacted high-entropy tokens by default.
- Before-and-after examples: `examples/dirty-repo`, `examples/clean-repo`, and checked outputs under `examples/outputs/`.
- Pre-commit integration guide: `docs/pre-commit-integration.md` documents
  install, hook config, failure behavior, baseline review, and CI reuse.
- Threat model: `docs/threat-model.md` states that the tool is not enterprise
  secret scanning and cannot guarantee absence of leaks.
- Rule and baseline semantics: `docs/release-notes-v0.8.0.md` documents
  `rule_id`, `rule_version`, structured evidence, baseline audit
  classifications, allowlists, and changed-files mode.
- Self-dogfooding: `docs/self-dogfooding.md` records
  `sec-writeups-public` as bootstrapped with tracked repo-sentinel config and
  baseline files, and `LogLens` as CI-integrated for repository hygiene and
  accidental sensitive filename checks. `telemetry-lab` is CI-integrated with
  generated artifacts ignored while source, configs, and sample inputs remain
  scanned.
- Tests / CI: local `python -m pytest -q` and `ruff check .`; GitHub Actions CI mirrors the documented dev workflow.
- Release evidence: production PyPI package, release workflow documentation, and release-day notes under `docs/`.
- Non-goals: full SAST, enterprise secret management, semantic code analysis, remote reporting, or centralized dashboards.

## Quick run

```bash
python -m pip install -e ".[dev]"
repo-sentinel scan --format json .
repo-sentinel scan --write-baseline baseline.json .
repo-sentinel scan --baseline baseline.json --fail-on-findings .
```

## Sample output

The CLI emits deterministic JSON or concise text summaries that surface:

- suspicious filename findings
- high-entropy findings with token bodies redacted by default
- structured secret-adjacent findings with `rule_id`, `rule_version`,
  `evidence`, and `remediation_hint`
- missing-standard-file findings
- baseline-suppressed versus unsuppressed results

The baseline path is intentionally reviewable: a previously accepted finding
can be checked back in and applied locally without changing scanner behavior.
`repo-sentinel baseline audit` classifies drift as active, stale, ambiguous, or
unmatched.

## What this proves

- deterministic CLI design with reviewer-friendly output contracts
- repository hygiene and lightweight secret-adjacent scanning discipline
- packaging, release, and pre-commit integration maturity
- a monitoring mindset applied to repository state

## Safety / boundaries

- local repository scanning only
- redaction is on by default for token-like findings
- no credential exfiltration or remote reporting behavior
- not positioned as a full SAST or enterprise secret-management platform

## Limitations

- heuristics are intentionally lightweight and conservative
- not a replacement for enterprise secret scanning
- does not guarantee that no credentials or sensitive material leaked
- does not identify every credential format
- no semantic code analysis
- no remote service, dashboard, or centralized triage workflow
- entropy and structured heuristic findings still require human review

## Current release posture

`repo-sentinel-lite` is already published to production PyPI. The current
source posture is v0.8 preparation: rule semantics, baseline audit,
allowlists, changed-files mode, and module boundaries are being hardened
without claiming enterprise secret-scanning coverage.

The v0.7 line theme is:

Adoption release for portfolio-level repository hygiene enforcement.

v0.7.1 is a polish release that keeps the PyPI README, GitHub README, release
notes, examples, and self-dogfooding evidence aligned.

The v0.8 source theme is:

Rule and Baseline Semantics Release.

## Next milestone

Keep production releases boring, reproducible, and documented while updating
consumer pins deliberately after each stable package release.
