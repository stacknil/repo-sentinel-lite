from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleDefinition:
    kind: str
    rule_id: str
    rule_version: str
    severity: str
    name: str
    short_description: str
    full_description: str
    remediation_hint: str


RULE_DEFINITIONS: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        kind="aws_access_key_id",
        rule_id="secret.aws_access_key_id",
        rule_version="1",
        severity="error",
        name="AWS Access Key ID Pattern",
        short_description="AWS access-key-like identifier detected.",
        full_description=(
            "Detects AWS access-key-like identifiers by provider prefix and "
            "length. This is a heuristic and does not validate the credential."
        ),
        remediation_hint=(
            "Rotate the key if it is real, remove it from source, and replace "
            "it with a safe fixture or environment reference."
        ),
    ),
    RuleDefinition(
        kind="assignment_context",
        rule_id="secret.assignment_context",
        rule_version="1",
        severity="warning",
        name="Secret Assignment Context",
        short_description="Secret-like assignment context detected.",
        full_description=(
            "Detects assignment contexts such as token=, api_key=, or "
            "password= with a non-placeholder value."
        ),
        remediation_hint=(
            "Confirm whether the value is synthetic. Prefer placeholders, "
            "environment variables, or an allowlist entry for reviewed fixtures."
        ),
    ),
    RuleDefinition(
        kind="github_token",
        rule_id="secret.github_token",
        rule_version="1",
        severity="error",
        name="GitHub Token Prefix",
        short_description="GitHub token-like prefix detected.",
        full_description=(
            "Detects GitHub token-like prefixes such as ghp_, gho_, ghs_, "
            "ghr_, ghu_, and github_pat_. This is a prefix heuristic."
        ),
        remediation_hint=(
            "Revoke the token if real, remove it from source, and replace it "
            "with a placeholder or secret manager reference."
        ),
    ),
    RuleDefinition(
        kind="high_entropy",
        rule_id="secret.high_entropy",
        rule_version="1",
        severity="error",
        name="High Entropy",
        short_description="High-entropy string detected.",
        full_description=(
            "Detects high-entropy strings that may indicate secrets."
        ),
        remediation_hint=(
            "Review the token. If it is real, rotate and remove it; if it is "
            "a fixture, baseline or allowlist it with a narrow exception."
        ),
    ),
    RuleDefinition(
        kind="missing_file",
        rule_id="repo.required_file_missing",
        rule_version="1",
        severity="warning",
        name="Missing Required File",
        short_description="Required repository file missing.",
        full_description="Detects required repository files that are missing.",
        remediation_hint=(
            "Add the required file or adjust required_files in "
            ".reposentinel.toml for this repository."
        ),
    ),
    RuleDefinition(
        kind="pem_private_key",
        rule_id="secret.pem_private_key",
        rule_version="1",
        severity="error",
        name="PEM Private Key Header",
        short_description="PEM private-key header detected.",
        full_description=(
            "Detects PEM private-key headers. This does not parse the full key "
            "but flags the strongest local evidence quickly."
        ),
        remediation_hint=(
            "Remove the private key from source, rotate it if real, and replace "
            "it with a synthetic fixture if documentation needs one."
        ),
    ),
    RuleDefinition(
        kind="suspicious_file",
        rule_id="repo.suspicious_filename",
        rule_version="1",
        severity="error",
        name="Suspicious Filename",
        short_description="Suspicious filename detected.",
        full_description=(
            "Detects suspicious filenames commonly associated with secrets."
        ),
        remediation_hint=(
            "Review whether the file belongs in source. Remove real secrets or "
            "baseline intentionally reviewed fixtures."
        ),
    ),
)

RULES_BY_KIND = {rule.kind: rule for rule in RULE_DEFINITIONS}
RULES_BY_ID = {rule.rule_id: rule for rule in RULE_DEFINITIONS}
SEVERITY_RANKS = {
    "warning": 1,
    "error": 2,
}


def rule_for_kind(kind: str) -> RuleDefinition:
    try:
        return RULES_BY_KIND[kind]
    except KeyError as exc:
        raise ValueError(f"unknown finding kind: {kind}") from exc


def rule_for_id(rule_id: str) -> RuleDefinition:
    try:
        return RULES_BY_ID[rule_id]
    except KeyError as exc:
        raise ValueError(f"unknown rule_id: {rule_id}") from exc
