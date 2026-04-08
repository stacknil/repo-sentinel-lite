# Contributing

Thanks for taking a look at `repo-sentinel-lite`.

## Issues and Changes

- Open an issue for bugs, false positives, or feature proposals.
- For security-sensitive reports, use the private reporting path described in
  [SECURITY.md](SECURITY.md).
- Keep pull requests focused. Small, reviewable changes are preferred.

## Local Validation

Run the stable local checks before opening a pull request:

```bash
python -m pytest -q
python -m ruff check .
python -m build
```

If your change touches the pre-commit provider, also run:

```bash
pre-commit validate-manifest .pre-commit-hooks.yaml
python tests/validate_pre_commit_provider.py
```

## Sanitization

Do not commit real secrets, credentials, private repository data, or
unsanitized logs and examples.
