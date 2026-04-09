# Production PyPI Gap List

## Gap 1

- blocker: Production GitHub/PyPI Trusted Publisher path is unconfirmed
- severity: high
- why it matters: A first production publish will fail if PyPI does not have a
  matching Trusted Publisher or pending publisher configuration for this
  repository and workflow, or if the GitHub environment expected by the
  workflow is missing.
- minimum fix: Create or confirm the GitHub environment `pypi`, then manually
  confirm the production PyPI Trusted Publisher setup for
  `stacknil/repo-sentinel-lite`, the workflow file
  `.github/workflows/release.yml`, and the environment name `pypi`.

## Gap 2

- blocker: The production project does not appear to exist yet on PyPI
- severity: high
- why it matters: The first production publish is also the project-creation
  event, which adds operational risk and requires the correct pending/new
  publisher flow.
- minimum fix: Confirm the pending/new publisher path in PyPI ahead of time so
  the first production publish can create `repo-sentinel-lite` intentionally.
