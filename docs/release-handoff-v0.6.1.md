# Release Handoff: v0.6.1

## Status

- Upstream fix commit on `main`: `61f8efbf68e7b5d7d1e49ad20e491a065963a307`
- Downstream adoption commit on `sec-writeups-public/main`: `0ea1c1a20155a498e9aa23c4e8358b635cf103de`
- Branch protection check for `sec-writeups-public/main`: not protected, so no PR was required

## Next Tag

- Latest existing tag: `v0.6.0`
- Next patch tag: `v0.6.1`

## Release Checklist

1. Confirm `main` still contains `61f8efbf68e7b5d7d1e49ad20e491a065963a307`.
2. Run the local preflight from [`RELEASE.md`](D:\OneDrive\Code\repo-sentinel-lite\RELEASE.md):

```bash
python -m pytest -q
ruff check .
python -m build
python -m twine check dist/*
```

3. Create and publish GitHub Release `v0.6.1` from `main`.
4. Verify the TestPyPI publish and entry points:

```bash
pip install --index-url https://test.pypi.org/simple/ --no-deps repo-sentinel-lite
repo-sentinel --help
python -m repo_sentinel --help
```

5. After the tag is live, update downstream consumers that are pinned to the raw commit SHA.

## Draft Release Notes

### Fixed

- `repo-sentinel scan` now auto-loads `.reposentinel-baseline.json` from the repository root when that file exists.
- The default baseline file is excluded from scanning so the scanner does not report findings against the baseline itself.
- The pre-commit provider keeps the required hook arguments in the provider-side hook entry, so consumers do not need custom `args` to make baseline-backed scans work.
- Provider validation now covers a real consumer-style repository with committed baseline data.

### Validation

- Upstream validation passed with `pytest`, `ruff`, and `tests/validate_pre_commit_provider.py`.
- Downstream validation passed in `sec-writeups-public` with:

```bash
python scripts/render_tags_doc.py --check
python scripts/check_markdown.py
python -m pre_commit run --files .pre-commit-config.yaml .reposentinel.toml .reposentinel-baseline.json
python -m pre_commit run repo-sentinel-error --hook-stage manual --all-files
```

- The first downstream fetch failure was transient GitHub HTTPS instability during hook environment setup, not a `repo-sentinel-lite` rule failure.
- Do not encode `GIT_HTTP_VERSION=HTTP/1.1` in repository files or docs. If GitHub HTTPS flakes again during manual verification, treat it as an environment retry, not a product change.

## Downstream Follow-Up

Once `v0.6.1` is released, replace the raw commit pin in `sec-writeups-public`:

- File: [`.pre-commit-config.yaml`](D:\OneDrive\Code\sec-writeups-public\.pre-commit-config.yaml)
- Change: `rev: 61f8efbf68e7b5d7d1e49ad20e491a065963a307` -> `rev: v0.6.1`
- Proposed commit message: `chore(repo-sentinel): pin provider to v0.6.1`

Re-run the same four downstream validation commands after that pin update.
