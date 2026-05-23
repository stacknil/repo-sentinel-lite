# Reviewer brief

## Problem

Small repositories still need basic hygiene checks, secret-adjacent scanning, and reviewer-visible baselines, but many teams do not need or want a heavyweight platform just to catch obvious problems.

## What it does

`repo-sentinel-lite` is a deterministic Python CLI that scans a repository for:

- suspicious filenames such as `.env`, `*.pem`, and `id_rsa`
- high-entropy strings that may look like secrets
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It supports `.reposentinel.toml` config, JSON baselines, redacted output by default, and pre-commit integration.

## Reviewer Evidence

- Reproducible command: `repo-sentinel scan --format json .`
- Deterministic outputs: stable JSON findings, text summaries, and baseline files with redacted high-entropy tokens by default.
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
- missing-standard-file findings
- baseline-suppressed versus unsuppressed results

The baseline path is intentionally reviewable: a previously accepted finding can be checked back in and applied locally without changing scanner behavior.

## What this proves

- deterministic CLI design with reviewer-friendly output contracts
- repository hygiene and lightweight secret-adjacent scanning discipline
- packaging, release, and pre-commit integration maturity
- a monitoring mindset applied to repository state

## Safety / boundaries

- local repository scanning only
- redaction is on by default for high-entropy findings
- no credential exfiltration or remote reporting behavior
- not positioned as a full SAST or enterprise secret-management platform

## Limitations

- heuristics are intentionally lightweight and conservative
- no semantic code analysis
- no remote service, dashboard, or centralized triage workflow
- entropy findings still require human review

## Current release posture

`repo-sentinel-lite` is already published to production PyPI. The current
focus is release hardening: keeping package metadata, baseline behavior,
redaction defaults, pre-commit integration, and CI validation stable across
small version bumps.

## Next milestone

Keep production releases boring, reproducible, and documented.
