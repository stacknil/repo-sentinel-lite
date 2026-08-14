from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ARTIFACT_ACTION = re.compile(
    r"actions/(?P<operation>upload|download)-artifact@(?P<version>[^\s]+)"
)


def test_artifact_action_versions() -> None:
    versions: dict[str, set[str]] = {"upload": set(), "download": set()}

    for workflow_path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = workflow_path.read_text(encoding="utf-8")
        for match in ARTIFACT_ACTION.finditer(workflow):
            versions[match.group("operation")].add(match.group("version"))

    assert versions == {"upload": {"v7"}, "download": {"v8"}}


def test_ci_and_release_keep_distribution_handoff_aligned() -> None:
    ci_workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    release_workflow = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")

    assert "artifact-handoff:" in ci_workflow
    assert "needs: build" in ci_workflow
    assert "actions/upload-artifact@v7" in ci_workflow
    assert "actions/download-artifact@v8" in ci_workflow
    assert "python -m twine check dist/*" in ci_workflow

    for workflow in (ci_workflow, release_workflow):
        assert "name: python-distributions" in workflow
        assert re.search(r"^\s+path: dist/\*$", workflow, re.MULTILINE)
        assert re.search(r"^\s+path: dist$", workflow, re.MULTILINE)

    assert release_workflow.count("actions/upload-artifact@v7") == 1
    assert release_workflow.count("actions/download-artifact@v8") == 2
