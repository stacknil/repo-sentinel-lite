# Release SOP

This project currently publishes to **TestPyPI only** via GitHub Releases and
Trusted Publishing. Keep this document aligned with the working release flow.

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
2. Create and publish a GitHub Release from `main` using tag `vX.Y.Z`.
   Publishing the release triggers `.github/workflows/release.yml`.
3. The workflow builds the package and publishes to TestPyPI via OIDC.

### TestPyPI Trusted Publisher values

Configure the Trusted Publisher in TestPyPI with:

- GitHub owner: `stacknil`
- Repository name: `repo-sentinel-lite`
- Workflow file: `.github/workflows/release.yml`
- Environment name: `testpypi`
- Project name: `repo-sentinel-lite`

### Post-release verification

1. Create a clean virtual environment.
2. Install from TestPyPI (no deps):

```bash
pip install --index-url https://test.pypi.org/simple/ --no-deps repo-sentinel-lite
```

3. Verify entry points:

```bash
repo-sentinel --help
python -m repo_sentinel --help
```
