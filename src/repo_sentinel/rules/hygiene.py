from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from ..config import is_suspicious_filename, normalize_path
from .registry import rule_for_kind


def detect_missing_files(root: Path, required_files: Sequence[str]) -> dict[str, bool]:
    return {
        normalize_path(filename): not _required_file_exists(root, filename)
        for filename in required_files
    }


def missing_file_findings(missing_files: dict[str, bool]) -> list[dict[str, object]]:
    rule = rule_for_kind("missing_file")
    return [
        {
            "evidence": {
                "path": normalize_path(path),
                "required": True,
            },
            "kind": rule.kind,
            "path": normalize_path(path),
            "remediation_hint": rule.remediation_hint,
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "severity": rule.severity,
        }
        for path, is_missing in missing_files.items()
        if is_missing
    ]


def suspicious_file_finding(path: str) -> dict[str, object]:
    rule = rule_for_kind("suspicious_file")
    normalized_path = normalize_path(path)
    return {
        "evidence": {
            "path": normalized_path,
            "pattern_family": "suspicious filename",
        },
        "kind": rule.kind,
        "path": normalized_path,
        "remediation_hint": rule.remediation_hint,
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
        "severity": rule.severity,
    }


def is_suspicious_path(path: str, patterns: Sequence[str]) -> bool:
    return is_suspicious_filename(path, patterns)


def _required_file_exists(root: Path, logical_path: str) -> bool:
    normalized_path = normalize_path(logical_path)
    parts = PurePosixPath(normalized_path).parts
    if (
        not parts
        or parts[0] == "/"
        or any(part in {"", ".", ".."} for part in parts)
    ):
        return False

    candidate = root.joinpath(*parts)
    if candidate.is_file():
        return True

    return _is_file_case_insensitive(root, parts)


def _is_file_case_insensitive(root: Path, parts: Sequence[str]) -> bool:
    current = root
    for part in parts:
        folded_part = part.casefold()
        try:
            match = next(
                (
                    entry
                    for entry in current.iterdir()
                    if entry.name.casefold() == folded_part
                ),
                None,
            )
        except OSError:
            return False
        if match is None:
            return False
        current = match

    return current.is_file()
