# repo-sentinel-lite

Minimal repository scanning CLI for deterministic repository hygiene checks.

`repo-sentinel-lite` scans a repository and emits stable JSON for:

- suspicious filenames such as `.env`, `*.pem`, `id_rsa`, and `*.kdbx`
- high-entropy strings that look like secrets
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It also supports `.reposentinel.toml` overrides and JSON baselines for
suppressing known findings.

## Installation

```bash
pip install repo-sentinel-lite
```

## Usage

Scan the current repository:

```bash
repo-sentinel scan
```

Scan a specific path and save a baseline:

```bash
repo-sentinel scan --write-baseline baseline.json path/to/repo
```

Scan with an existing baseline applied:

```bash
repo-sentinel scan --baseline baseline.json path/to/repo
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
