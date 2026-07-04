# repo-sentinel-lite

Deterministic Python CLI for repository hygiene checks, lightweight secret
scanning, and baseline-backed pre-commit validation.

`repo-sentinel-lite` scans a repository and emits stable JSON for:

- suspicious filenames such as `.env`, `*.pem`, `id_rsa`, and `*.kdbx`
- high-entropy strings that look like secrets
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It also supports `.reposentinel.toml` overrides, JSON baselines for suppressing
known findings, and a pre-commit provider for repository-local enforcement.
High-entropy tokens are redacted in CLI output and generated baselines by
default.

## Install

Install from production PyPI:

```bash
python -m pip install repo-sentinel-lite
```

Requires Python 3.11 or newer.

## Usage

More copy-pasteable CLI workflows are in
[`docs/cli-recipes.md`](docs/cli-recipes.md).
For the shortest consumer setup path, see
[`docs/consumer-minimal-setup.md`](docs/consumer-minimal-setup.md).
For baseline review expectations and a sample baseline, see
[`docs/baseline-review.md`](docs/baseline-review.md).
For output stability and CI artifact guidance, see
[`docs/output-format-stability.md`](docs/output-format-stability.md).
For pre-commit provider setup, see
[`docs/pre-commit-integration.md`](docs/pre-commit-integration.md).
For threat model boundaries and non-goals, see
[`docs/threat-model.md`](docs/threat-model.md).
For self-dogfooding status, see
[`docs/self-dogfooding.md`](docs/self-dogfooding.md).
For before-and-after scanner examples, see [`examples/`](examples/).
The v0.7 adoption plan is tracked in
[`docs/v0.7-adoption-release.md`](docs/v0.7-adoption-release.md).
Release notes for v0.7.1 are tracked in
[`docs/release-notes-v0.7.1.md`](docs/release-notes-v0.7.1.md).

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

Temporarily scan without the repository-root default baseline:

```bash
repo-sentinel scan --no-default-baseline path/to/repo
```

Fail with exit code `1` when unsuppressed findings remain:

```bash
repo-sentinel scan --fail-on-findings path/to/repo
```

Reveal full high-entropy tokens only when you explicitly need to inspect them:

```bash
repo-sentinel scan --reveal-secrets path/to/repo
```

Use a `.reposentinel.toml` config to ignore paths or adjust thresholds:

```toml
ignore_globs = ["dist/**", ".venv/**"]
entropy_threshold = 4.2
max_text_file_size = 1048576
```

Child-glob ignores such as `fixtures/*`, `fixtures/**`, and `fixtures/**/*`
prune the matching directory during traversal.

Common generated and dependency directories such as `.venv`, `venv`,
`.venv-*`, `node_modules`, `dist`, `dist-*`, `build`, `.tox`, `.nox`,
`.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `*.egg-info`, `coverage`,
`htmlcov`, and `__pycache__` are ignored by default.
Text files larger than `max_text_file_size` bytes are skipped for high-entropy
content scanning by default.

## Local development

Use Python 3.11 or newer, then run:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check .
```

These commands match the GitHub Actions CI workflow:
`.github/workflows/ci.yml`
