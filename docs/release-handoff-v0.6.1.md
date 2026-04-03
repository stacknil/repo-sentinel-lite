# Release Handoff Record: v0.6.1

This document is a historical handoff artifact for the `v0.6.1` release that
was already created. Keep it as release context, not as the current release
SOP.

## Status

- Release tag: `v0.6.1`
- Release commit: `61f8efbf68e7b5d7d1e49ad20e491a065963a307`
- GitHub release object exists for `v0.6.1`
- Downstream remote-provider adoption completed on `sec-writeups-public/main`
- Branch protection check for `sec-writeups-public/main` at handoff time: not protected, so no PR was required

## Release Notes Summary

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

The downstream raw commit pin was later replaced with `rev: v0.6.1` in
`sec-writeups-public`, and the same four validation commands were re-run after
that pin update.
