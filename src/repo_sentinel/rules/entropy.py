from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from ..config import (
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    scoped_comment_allows_rule,
    token_sha256,
)
from .registry import rule_for_kind

TOKEN_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{{{HIGH_ENTROPY_MIN_LENGTH},}}"
    r"(?:={1,2})?)(?![A-Za-z0-9+/_=-])"
)


@dataclass(frozen=True, order=True)
class EntropyFinding:
    file: str
    line: int
    token: str
    entropy: float

    def to_dict(self) -> dict[str, object]:
        return {
            "entropy": self.entropy,
            "file": self.file,
            "line": self.line,
            "token": self.token,
        }


def calculate_shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def find_high_entropy_strings(
    file_path: str, text: str, threshold: float = HIGH_ENTROPY_THRESHOLD
) -> list[EntropyFinding]:
    findings: list[EntropyFinding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in TOKEN_PATTERN.finditer(line):
            token = match.group(1)
            entropy = round(calculate_shannon_entropy(token), 4)
            if entropy >= threshold:
                findings.append(
                    EntropyFinding(
                        file=file_path,
                        line=line_number,
                        token=token,
                        entropy=entropy,
                    )
                )

    return findings


def detect_high_entropy_findings(
    file_path: str, text: str, threshold: float = HIGH_ENTROPY_THRESHOLD
) -> list[dict[str, object]]:
    rule = rule_for_kind("high_entropy")
    lines = text.splitlines()
    findings: list[dict[str, object]] = []

    for finding in find_high_entropy_strings(file_path, text, threshold):
        if scoped_comment_allows_rule(
            lines, finding.line, kind=rule.kind, rule_id=rule.rule_id
        ):
            continue

        findings.append(
            {
                "entropy": finding.entropy,
                "evidence": {
                    "entropy": finding.entropy,
                    "line": finding.line,
                    "token_sha256": token_sha256(finding.token),
                },
                "file": finding.file,
                "kind": rule.kind,
                "line": finding.line,
                "path": finding.file,
                "remediation_hint": rule.remediation_hint,
                "rule_id": rule.rule_id,
                "rule_version": rule.rule_version,
                "severity": rule.severity,
                "token": finding.token,
            }
        )

    return findings
