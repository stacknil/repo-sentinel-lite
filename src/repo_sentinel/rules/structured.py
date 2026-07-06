from __future__ import annotations

import re
from collections.abc import Sequence

from ..config import (
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    scoped_comment_allows_rule,
    token_sha256,
)
from .entropy import calculate_shannon_entropy
from .registry import rule_for_kind

PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)
GITHUB_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
AWS_ACCESS_KEY_ID_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?P<name>token|secret|api[_-]?key|password|passwd|credential|"
    r"access[_-]?key)\b\s*[:=]\s*(?P<quote>[\"']?)(?P<value>[^\"'\s#;]{8,})"
)
SOURCE_EXPRESSION_DEREFERENCE_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\.")
SOURCE_EXPRESSION_MARKERS = frozenset("()[]{}")
PLACEHOLDER_VALUES = {
    "changeme",
    "dummy",
    "example",
    "example-token",
    "placeholder",
    "redacted",
    "sample",
    "test",
    "todo",
}


def detect_structured_secret_findings(
    file_path: str, text: str
) -> list[dict[str, object]]:
    lines = text.splitlines()
    findings: list[dict[str, object]] = []

    for line_number, line in enumerate(lines, start=1):
        findings.extend(_pem_private_key_findings(file_path, lines, line_number, line))
        findings.extend(_github_token_findings(file_path, lines, line_number, line))
        findings.extend(_aws_access_key_findings(file_path, lines, line_number, line))
        findings.extend(
            _assignment_context_findings(file_path, lines, line_number, line)
        )

    return findings


def _pem_private_key_findings(
    file_path: str, lines: Sequence[str], line_number: int, line: str
) -> list[dict[str, object]]:
    rule = rule_for_kind("pem_private_key")
    if not PEM_PRIVATE_KEY_PATTERN.search(line):
        return []
    if scoped_comment_allows_rule(
        lines, line_number, kind=rule.kind, rule_id=rule.rule_id
    ):
        return []
    return [
        {
            "evidence": {
                "line": line_number,
                "pattern": "PEM private-key header",
            },
            "file": file_path,
            "kind": rule.kind,
            "line": line_number,
            "path": file_path,
            "remediation_hint": rule.remediation_hint,
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "severity": rule.severity,
        }
    ]


def _github_token_findings(
    file_path: str, lines: Sequence[str], line_number: int, line: str
) -> list[dict[str, object]]:
    rule = rule_for_kind("github_token")
    if scoped_comment_allows_rule(
        lines, line_number, kind=rule.kind, rule_id=rule.rule_id
    ):
        return []
    return [
        _token_finding(
            file_path=file_path,
            line_number=line_number,
            token=match.group(0),
            rule_kind=rule.kind,
            evidence_label="GitHub token prefix",
        )
        for match in GITHUB_TOKEN_PATTERN.finditer(line)
    ]


def _aws_access_key_findings(
    file_path: str, lines: Sequence[str], line_number: int, line: str
) -> list[dict[str, object]]:
    rule = rule_for_kind("aws_access_key_id")
    if scoped_comment_allows_rule(
        lines, line_number, kind=rule.kind, rule_id=rule.rule_id
    ):
        return []
    return [
        _token_finding(
            file_path=file_path,
            line_number=line_number,
            token=match.group(0),
            rule_kind=rule.kind,
            evidence_label="AWS access-key-like prefix",
        )
        for match in AWS_ACCESS_KEY_ID_PATTERN.finditer(line)
    ]


def _assignment_context_findings(
    file_path: str, lines: Sequence[str], line_number: int, line: str
) -> list[dict[str, object]]:
    rule = rule_for_kind("assignment_context")
    if scoped_comment_allows_rule(
        lines, line_number, kind=rule.kind, rule_id=rule.rule_id
    ):
        return []

    findings: list[dict[str, object]] = []
    for match in ASSIGNMENT_PATTERN.finditer(line):
        token = match.group("value").rstrip(",)")
        if not match.group("quote") and _looks_like_source_expression(token):
            continue
        if _is_placeholder_value(token):
            continue
        if _is_high_entropy_token(token):
            continue
        findings.append(
            _token_finding(
                file_path=file_path,
                line_number=line_number,
                token=token,
                rule_kind=rule.kind,
                evidence_label=f"assignment to {match.group('name')}",
            )
        )
    return findings


def _token_finding(
    *,
    file_path: str,
    line_number: int,
    token: str,
    rule_kind: str,
    evidence_label: str,
) -> dict[str, object]:
    rule = rule_for_kind(rule_kind)
    return {
        "evidence": {
            "line": line_number,
            "pattern": evidence_label,
            "token_sha256": token_sha256(token),
        },
        "file": file_path,
        "kind": rule.kind,
        "line": line_number,
        "path": file_path,
        "remediation_hint": rule.remediation_hint,
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
        "severity": rule.severity,
        "token": token,
    }


def _is_placeholder_value(value: str) -> bool:
    normalized = value.strip("\"'").strip("<>").casefold()
    return (
        normalized in PLACEHOLDER_VALUES
        or normalized.startswith("example_")
        or normalized.startswith("placeholder_")
        or normalized.startswith("sample_")
        or normalized.startswith("test_")
    )


def _looks_like_source_expression(value: str) -> bool:
    return any(marker in value for marker in SOURCE_EXPRESSION_MARKERS) or bool(
        SOURCE_EXPRESSION_DEREFERENCE_PATTERN.search(value)
    )


def _is_high_entropy_token(value: str) -> bool:
    if len(value) < HIGH_ENTROPY_MIN_LENGTH:
        return False
    return calculate_shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD
