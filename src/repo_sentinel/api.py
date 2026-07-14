"""Secure-by-default public Python API."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .redaction import redact_report
from .scanner import scan_repository as _scan_repository_sensitive


def scan_repository(
    root: Path,
    *,
    changed_paths: Iterable[str] | None = None,
    reveal_secrets: bool = False,
) -> dict[str, object]:
    """Scan a repository and return a token-redacted report by default.

    Setting ``reveal_secrets`` returns the sensitive in-memory report and should
    be limited to intentional local investigation.
    """
    report = _scan_repository_sensitive(root, changed_paths=changed_paths)
    if reveal_secrets:
        return report
    return redact_report(report)
