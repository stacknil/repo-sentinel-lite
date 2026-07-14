# repo-sentinel-lite

Deterministic Python CLI for repository hygiene checks, lightweight
secret-adjacent scanning, and baseline-backed pre-commit validation.

`repo-sentinel-lite` scans a repository and emits stable JSON for:

- suspicious filenames such as `.env`, `*.pem`, `id_rsa`, and `*.kdbx`
- high-entropy strings that look like secrets
- structured secret-adjacent patterns such as PEM private-key headers,
  GitHub-token-like prefixes, AWS access-key-like prefixes, and generic
  `token=` or `api_key=` assignment contexts
- missing standard files such as `README.md`, `LICENSE`, and `.gitignore`

It also supports `.reposentinel.toml` overrides, scoped allowlists, JSON
baselines for suppressing known findings, baseline drift audits, changed-file
scans, and a pre-commit provider for repository-local enforcement. Token-like
values are redacted in CLI output and generated baselines by default.

The detector set is intentionally heuristic. A clean scan is useful repository
hygiene evidence, not proof that no credential exists in the repository or its
history.

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
For the v0.8 synthetic performance envelope, see
[`docs/performance-envelope-v0.8.md`](docs/performance-envelope-v0.8.md).
For self-dogfooding status, see
[`docs/self-dogfooding.md`](docs/self-dogfooding.md).
For the short external case study, see
[How repo-sentinel-lite Dogfoods Repository Hygiene](docs/case-study-self-dogfooding.md).
For near-term review boundaries, see [`ROADMAP.md`](ROADMAP.md).
For before-and-after scanner examples, see [`examples/`](examples/).
The v0.7 adoption plan is tracked in
[`docs/v0.7-adoption-release.md`](docs/v0.7-adoption-release.md).
Release notes for v0.7.1 are tracked in
[`docs/release-notes-v0.7.1.md`](docs/release-notes-v0.7.1.md).
Release notes for v0.8.0 are tracked in
[`docs/release-notes-v0.8.0.md`](docs/release-notes-v0.8.0.md).

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

Audit baseline drift without suppressing the classification output:

```bash
repo-sentinel baseline audit --baseline baseline.json path/to/repo
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

### Python API

The package-level API returns a deep-redacted report by default:

```python
from pathlib import Path

from repo_sentinel import scan_repository

report = scan_repository(Path("path/to/repo"))
```

Pass `reveal_secrets=True` only for an intentional local investigation:

```python
sensitive_report = scan_repository(
    Path("path/to/repo"),
    reveal_secrets=True,
)
```

The revealed result can contain credential-like token bodies. Do not log,
upload, or persist it as an ordinary report. Existing low-level integrations
that import `repo_sentinel.scanner.scan_repository` receive the sensitive
internal report for compatibility; new integrations should use the package-level
API above.

Use a `.reposentinel.toml` config to ignore paths or adjust thresholds:

```toml
ignore_globs = ["dist/**", ".venv/**"]
entropy_threshold = 4.2
max_text_file_size = 1048576

[allowlist]
paths = ["fixtures/**"]
rules = ["repo.suspicious_filename"]
token_hashes = ["sha256:3eb1bd439947"]
```

Use `rule_id` values from JSON findings when writing rule-scoped allowlists.

Configuration loading fails closed. Only an absent `.reposentinel.toml` uses
defaults; unreadable files, invalid TOML or values, and unknown top-level or
`[allowlist]` keys return CLI exit code `2`. Diagnostics name the repository-
relative config file without printing the scanned root's absolute path.

The legacy aliases `suspicious_patterns`, `allowlist_paths`, `allowlist_rules`,
and `allowlist_token_hashes` remain accepted for compatibility. New configs
should use `suspicious_filenames` and the nested `[allowlist]` keys shown above.

Child-glob ignores such as `fixtures/*`, `fixtures/**`, and `fixtures/**/*`
prune the matching directory during traversal.

Common generated and dependency directories such as `.venv`, `venv`,
`.venv-*`, `node_modules`, `dist`, `dist-*`, `build`, `.tox`, `.nox`,
`.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `*.egg-info`, `coverage`,
`htmlcov`, and `__pycache__` are ignored by default.
Text files larger than `max_text_file_size` bytes are skipped for high-entropy
content scanning by default.
The default [symlink policy](docs/symlink-policy.md) never follows file or
directory symlinks. Link names still participate in hygiene checks, while
target names and contents do not. Directory links and loops are pruned before
descent; changed-file paths that cross a directory link are skipped.

When content inspection is skipped, JSON adds a deterministic `coverage`
object with repository-relative paths, totals, and one of `binary`, `oversize`,
`symlink_policy`, `unreadable`, or `unsupported_encoding` for each skipped
file. Text output appends the same list, and SARIF stores it in the run-level
`properties.repoSentinelCoverage` property. Coverage diagnostics are
informational: they do not change exit status or become suppressible findings.
The field is omitted when no discovered file is skipped, preserving existing
clean-scan output. When directory symlinks are skipped, coverage also adds
`directories_skipped` and `skipped_directories` without changing the file
counters.

For pre-commit or local review paths that already know the changed files, scan
only those files while keeping repository-level required-file checks:

```bash
repo-sentinel scan --changed-files path/to/repo src/app.py docs/example.md
```

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
