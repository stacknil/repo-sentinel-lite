# Release SOP

This project publishes GitHub prereleases to **TestPyPI** and stable GitHub
releases to **PyPI** via GitHub Releases and Trusted Publishing. Keep this
document aligned with the working release flow.

### Local preflight

Run from repo root:

```bash
python -m pytest -q
ruff check .
python -m build
python -m twine check dist/*
```

### GitHub Release trigger flow

1. Push to `main`.
2. Update the package version in both `pyproject.toml` and
   `src/repo_sentinel/__init__.py` to `X.Y.Z`.
3. Create the release tag locally from `main`, then push the tag:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

4. Create and publish the GitHub Release from the pushed tag:

```bash
gh release create vX.Y.Z --verify-tag
```

5. For a TestPyPI smoke prerelease, create the GitHub release as a prerelease:

```bash
gh release create vX.Y.ZrcN --verify-tag --prerelease
```

6. Publishing the release triggers `.github/workflows/release.yml`.
7. The workflow builds distributions once, then:
   - publishes GitHub prereleases to TestPyPI
   - publishes stable GitHub releases to PyPI

Stable production releases require a matching production PyPI Trusted Publisher
or pending publisher configuration before the release is published.

`--verify-tag` keeps release creation from implicitly creating the tag on the
server. That removes ambiguity about what commit the release actually points to.
The release workflow also validates that the pushed tag matches the package
version before it builds distributions.

### TestPyPI Trusted Publisher values

Configure the Trusted Publisher in TestPyPI with:

- GitHub owner: `stacknil`
- Repository name: `repo-sentinel-lite`
- Workflow file: `.github/workflows/release.yml`
- Environment name: `testpypi`
- Project name: `repo-sentinel-lite`

### Production PyPI Trusted Publisher values

Configure the Trusted Publisher or pending publisher in PyPI with:

- GitHub owner: `stacknil`
- Repository name: `repo-sentinel-lite`
- Workflow file: `.github/workflows/release.yml`
- Environment name: `pypi`
- Project name: `repo-sentinel-lite`

If the production project does not exist yet, the first successful stable
publish can create it through the pending/new publisher flow.

### Post-release verification

1. Create a clean virtual environment.
2. Install from the target index:

For TestPyPI prereleases:

```bash
pip install --index-url https://test.pypi.org/simple/ --no-deps repo-sentinel-lite
```

For stable production releases:

```bash
pip install --no-deps repo-sentinel-lite
```

3. Verify entry points:

```bash
repo-sentinel --help
python -m repo_sentinel --help
```

### SARIF fallback workflow

When GitHub code scanning is unavailable for this private repository, use
`.github/workflows/code-scanning.yml` as the fallback path.

1. Open the repository `Actions` tab.
2. Run the `Code Scanning` workflow manually.
3. After the run completes, open the workflow run and download the
   `repo-sentinel-lite-sarif` artifact.
4. The artifact contains the generated `results.sarif` file.
