# Production PyPI Manual Checklist

- Confirm whether the production PyPI project `repo-sentinel-lite` already
  exists.
- If the project does not exist, use the pending/new publisher flow in PyPI for
  the first successful stable publish.
- Confirm the Trusted Publisher fields exactly:
  - GitHub owner: `stacknil`
  - repository: `repo-sentinel-lite`
  - workflow file: `.github/workflows/release.yml`
  - environment: `pypi`
- Create the GitHub environment `pypi` if it does not already exist, then
  confirm the environment name matches the PyPI configuration exactly.
- Confirm the production publish job in `.github/workflows/release.yml` still
  has `permissions: id-token: write`.
- Confirm the chosen stable version is `0.6.2` unless a stronger release-day
  reason emerges.
- Confirm repository version metadata is already set to `0.6.2` before tagging.
- Confirm final preflight commands:
  - `python -m pytest -q`
  - `python -m ruff check .`
  - `python -m build`
  - `python -m twine check dist/*`
- Confirm post-release verification steps:
  - open the production PyPI project page
  - install `repo-sentinel-lite` from production PyPI in a clean Python 3.14
    environment
  - verify `repo-sentinel --help`
  - verify `python -m repo_sentinel --help`
