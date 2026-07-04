# How repo-sentinel-lite Dogfoods Repository Hygiene

`repo-sentinel-lite` is more credible as a small hygiene tool when its own
portfolio uses it under visible constraints. The dogfooding goal is not to
claim that every repository is permanently clean. It is to make the adoption
decision reviewable.

The maintained [self-dogfooding matrix](self-dogfooding.md) records three
different consumer shapes: a security-notes repository with a reviewed
baseline, a C++ repository with a narrow filename-hygiene gate, and a telemetry
repository with generated artifacts excluded while source inputs remain in
scope.

## The evidence is configuration, not a badge

A useful adoption record answers five questions:

1. Which repository is scanned?
2. Which command or CI entry point runs the scan?
3. Which paths or checks are excluded, and why?
4. Is a baseline present, and how is it reviewed?
5. What follow-up remains when configuration or package versions drift?

Those details matter more than a generic "scanner enabled" statement. The
tool's checked-in configuration, baseline, workflow, and gate command form the
review surface.

## Different repositories need different boundaries

The current portfolio examples intentionally do not share one universal
configuration:

- `sec-writeups-public` uses project-specific ignores and a reviewed baseline
  because generated reports would otherwise duplicate authored evidence.
- `LogLens` keeps a narrow repository-hygiene and suspicious-filename gate.
  Fixture-heavy C++ content makes broad entropy scanning a poor default for
  that repository.
- `telemetry-lab` ignores reproducible generated artifacts while leaving
  source, configuration, and raw synthetic inputs in scope. It uses a reviewed
  entropy threshold instead of checking in a noise-heavy baseline.

These are policy decisions, not scanner truths. A reviewer should be able to
see why an ignore, threshold, or baseline entry exists and whether it still
matches the repository's purpose.

## Reproduce the consumer path

The shortest neutral consumer setup is documented in
[consumer minimal setup](consumer-minimal-setup.md). A local gate can remain as
small as:

```bash
python -m pip install repo-sentinel-lite
repo-sentinel scan --fail-on-severity error --format text .
```

Repositories that need suppressions should use the
[baseline review rules](baseline-review.md) rather than silently widening
ignores. High-entropy token bodies remain redacted by default.

## What dogfooding does not prove

The adoption matrix is point-in-time evidence. It does not guarantee that a
consumer stays green, that every credential format is detected, or that no
sensitive material has leaked. `repo-sentinel-lite` remains a local,
lightweight heuristic tool, not enterprise secret scanning, SAST, or a remote
triage service.

The controlled external review question is therefore narrow: does each
consumer's configuration expose a sensible, reproducible hygiene policy with
clear exceptions?
