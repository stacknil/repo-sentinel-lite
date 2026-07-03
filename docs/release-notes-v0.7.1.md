# v0.7.1 Release Notes

Polish release for the v0.7 adoption story.

## Documentation Polish

- Adds a minimal consumer setup guide for repositories that want a small
  `repo-sentinel-lite` hygiene gate without reading the full adoption docs.
- Adds expected-output summaries to the example fixtures so reviewers can see
  the dirty and clean repository contracts at a glance.
- Extends the self-dogfooding matrix with the exact gate command used by
  `sec-writeups-public`, `LogLens`, and `telemetry-lab`.
- Keeps GitHub README, PyPI README, and release notes aligned around production
  PyPI installation, Python 3.11+ support, redaction defaults, baseline review,
  pre-commit integration, and self-dogfooding evidence.

## Package And Release Posture

- Bumps package metadata to `0.7.1`.
- Updates pre-commit provider examples to pin `rev: v0.7.1`.
- Preserves the v0.7 compatibility contract: Python 3.11 or newer, no baseline
  schema migration, and no new large feature surface.

## Code Polish

- Avoids materializing directory entries during the case-insensitive required
  file fallback, keeping the check streaming and behavior-preserving.

## Compatibility And Migration

- Requires Python 3.11 or newer.
- No baseline schema migration is required.
- Consumers using pre-commit can update the provider `rev` to `v0.7.1` after
  the release is published.
