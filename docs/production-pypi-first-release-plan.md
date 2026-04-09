# First Production PyPI Release Plan

1. Confirm production PyPI Trusted Publisher configuration.
   Ensure the GitHub owner, repository, workflow filename, and any production
   environment name match exactly.
2. Confirm project existence versus the pending publisher path.
   Treat `repo-sentinel-lite` as a new production project unless PyPI-side
   verification proves otherwise.
3. Confirm the prepared stable version.
   Verify `pyproject.toml` and `src/repo_sentinel/__init__.py` both read
   `0.6.2` before tagging.
4. Run local preflight checks.
   Run `python -m pytest -q`, `python -m ruff check .`,
   `python -m build`, and `python -m twine check dist/*`.
5. Create the release-prep commit.
   Keep the commit scoped to the production version bump and any strictly
   necessary release-path updates.
6. Create the production tag.
   Tag `v0.6.2` from the intended release commit.
7. Push the commit and tag.
   Push `main` and then push the release tag.
8. Monitor the GitHub Release workflow.
   Publish a stable GitHub release, not a prerelease, so the workflow routes to
   the production PyPI publish job. Watch both the build job and the production
   publish job through completion.
9. Verify the production PyPI project page and install.
   Check the project page, install from production PyPI in a clean environment,
   and verify `repo-sentinel --help` and `python -m repo_sentinel --help`.
10. Update README install instructions if production publish succeeds.
   Replace the current GitHub-source install guidance with the production PyPI
   install path or clearly document both paths.
