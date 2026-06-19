from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_support_metadata_docs_and_ci_are_aligned() -> None:
    pyproject = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    classifiers = set(pyproject["project"]["classifiers"])

    assert pyproject["project"]["requires-python"] == ">=3.11"
    assert pyproject["tool"]["ruff"]["target-version"] == "py311"
    assert "Requires Python 3.11 or newer." in readme
    assert "Use Python 3.11 or newer, then run:" in readme
    assert "Requires Python 3.14." not in readme
    assert "Requires-Python: >=3.11" in ci

    for version in ("3.11", "3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {version}" in classifiers
        assert f"Classifier: Programming Language :: Python :: {version}" in ci
        assert f'          - "{version}"' in ci


def test_release_and_support_workflows_run_on_lowest_supported_python() -> None:
    workflow_paths = (
        ROOT / ".github" / "workflows" / "code-scanning.yml",
        ROOT / ".github" / "workflows" / "pre-commit-provider.yml",
        ROOT / ".github" / "workflows" / "release.yml",
    )

    for path in workflow_paths:
        workflow = path.read_text(encoding="utf-8")
        assert 'python-version: "3.11"' in workflow
        assert 'python-version: "3.14"' not in workflow
