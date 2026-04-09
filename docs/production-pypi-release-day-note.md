# Production PyPI Release-Day Note

- exact commit prepared for release day: the single release-prep commit with
  message `chore(release): prepare 0.6.2 production release candidate`
- exact version prepared: `0.6.2`

Manual confirmations still required before push/tag:

- production PyPI Trusted Publisher or pending publisher exists for:
  - owner `stacknil`
  - repository `repo-sentinel-lite`
  - workflow `.github/workflows/release.yml`
  - environment `pypi`
- GitHub environment `pypi` exists and matches the PyPI configuration

Release-day command sequence:

```bash
python -m pytest -q
python -m ruff check .
python -m build
python -m twine check dist/*
git push origin main
git tag -a v0.6.2 -m "v0.6.2"
git push origin v0.6.2
gh release create v0.6.2 --verify-tag
```

Post-release verification:

1. Confirm the GitHub Actions `Release` workflow succeeds.
2. Confirm the production PyPI project page exists.
3. Confirm `pip install repo-sentinel-lite==0.6.2` succeeds from production
   PyPI in a clean Python 3.14 environment.
4. Confirm `repo-sentinel --help` and `python -m repo_sentinel --help` work.
5. Update README install instructions in a follow-up commit if desired.
