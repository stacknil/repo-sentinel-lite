# v0.8.1 Release Notes

Theme: Registry Recovery Patch.

## What Changed

- Fixes release tag verification so it reads the package version without
  importing the package before installation.
- Publishes the v0.8 line to PyPI under a new immutable patch version after the
  v0.8.0 GitHub Release workflow stopped before registry publication.
- Updates consumer installation and pre-commit examples to pin `v0.8.1`.

## Compatibility Notes

- Scanner, report, baseline, configuration, and changed-file gate semantics are
  unchanged from v0.8.0.
- Existing v0.8.0 Git tags and GitHub Release records remain unchanged.
- Consumers can move from v0.7.1 or a source installation of v0.8.0 to v0.8.1
  without changing configuration or baselines.

## Boundary

Rule-version drift classification remains follow-up work. This patch does not
add `rule_changed` or change fingerprint identity.
