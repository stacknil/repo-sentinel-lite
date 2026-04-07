# repo-sentinel-lite

Deterministic Python CLI for repository hygiene checks, lightweight secret
scanning, and baseline-backed pre-commit validation.

`repo-sentinel-lite` scans a repository and emits stable JSON for:

- suspicious filenames such as `.env`, `*.pem`, `id_rsa`, and `*.kdbx`
- high-entropy strings that look like secrets
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It also supports `.reposentinel.toml` overrides, JSON baselines for suppressing
known findings, and a pre-commit provider for repository-local enforcement.

## Install

Install from the latest tagged GitHub source release:

```bash
python -m pip install "git+https://github.com/stacknil/repo-sentinel-lite.git@v0.6.1"
```

Requires Python 3.14.

`repo-sentinel-lite` is not published on production PyPI yet.

## Usage

More copy-pasteable CLI workflows are in
[`docs/cli-recipes.md`](docs/cli-recipes.md).

Scan the current repository. This defaults to deterministic JSON output:

```bash
repo-sentinel scan
```

Emit deterministic JSON explicitly for a specific path:

```bash
repo-sentinel scan --format json path/to/repo
```

Render a concise text summary for a specific path:

```bash
repo-sentinel scan --format text path/to/repo
```

Scan a specific path and save a baseline:

```bash
repo-sentinel scan --write-baseline baseline.json path/to/repo
```

Scan with an existing baseline applied:

```bash
repo-sentinel scan --baseline baseline.json path/to/repo
```

If the scanned repository already contains `.reposentinel-baseline.json`,
`repo-sentinel scan` applies it automatically.

Fail with exit code `1` when unsuppressed findings remain:

```bash
repo-sentinel scan --fail-on-findings path/to/repo
```

Use a `.reposentinel.toml` config to ignore paths or adjust thresholds:

```toml
ignore_globs = ["dist/*", ".venv/*"]
entropy_threshold = 4.2
```

## Local development

Use Python 3.14, then run:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check .
```

These commands match the GitHub Actions CI workflow:
`.github/workflows/ci.yml`
