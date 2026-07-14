from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from . import walk as _walk
from .baseline import (
    BASELINE_SCHEMA_VERSION,
    apply_baseline,
    audit_baseline,
    baseline_from_report,
    format_baseline,
    format_baseline_audit,
    load_baseline,
    prune_baseline,
    update_baseline,
    write_baseline,
)
from .config import (
    CONFIG_FILENAME,
    DEFAULT_BASELINE_FILENAME,
    DEFAULT_IGNORE_GLOBS,
    DEFAULT_MAX_TEXT_FILE_SIZE,
    HIGH_ENTROPY_MIN_LENGTH,
    HIGH_ENTROPY_THRESHOLD,
    REQUIRED_FILES,
    SUSPICIOUS_FILENAMES,
    is_finding_allowlisted,
    is_suspicious_filename,
    load_scan_config,
    relative_path,
)
from .coverage import build_coverage
from .redaction import (
    REDACTED_TOKEN_PREFIX,
    redact_report,
    redact_token,
    render_token,
)
from .report import (
    SEVERITY_RANKS,
    build_report,
    format_report,
    format_text_report,
    has_findings,
    has_findings_at_or_above_severity,
    normalize_report,
)
from .rules import (
    EntropyFinding,
    calculate_shannon_entropy,
    detect_high_entropy_findings,
    detect_missing_files,
    detect_structured_secret_findings,
    find_high_entropy_strings,
    is_suspicious_path,
    missing_file_findings,
    suspicious_file_finding,
)
from .sarif import format_sarif_report
from .walk import TextReadSkipped, inspect_text_file, iter_files, read_text_file

os = _walk.os


def scan_repository(
    root: Path, *, changed_paths: Iterable[str] | None = None
) -> dict[str, object]:
    resolved_root = root.resolve()
    config = load_scan_config(resolved_root)
    findings: list[dict[str, object]] = []
    files_inspected = 0
    skipped_files: list[dict[str, object]] = []

    for path in iter_files(
        resolved_root,
        config.ignore_globs,
        changed_paths=changed_paths,
    ):
        relative = relative_path(path, resolved_root)

        if is_suspicious_path(relative, config.suspicious_filenames):
            _append_if_not_allowlisted(
                findings,
                suspicious_file_finding(relative),
                config.allowlist,
            )

        read_result = inspect_text_file(path, config.max_text_file_size)
        if isinstance(read_result, TextReadSkipped):
            skipped_files.append({"path": relative, "reason": read_result.reason})
            continue
        files_inspected += 1
        text = read_result.text

        for finding in detect_high_entropy_findings(
            relative, text, threshold=config.entropy_threshold
        ):
            _append_if_not_allowlisted(findings, finding, config.allowlist)
        for finding in detect_structured_secret_findings(relative, text):
            _append_if_not_allowlisted(findings, finding, config.allowlist)

    missing_files = detect_missing_files(resolved_root, config.required_files)
    for finding in missing_file_findings(missing_files):
        if is_finding_allowlisted(finding, config.allowlist):
            missing_files[str(finding["path"])] = False
            continue
        findings.append(finding)

    coverage = build_coverage(files_inspected, skipped_files) if skipped_files else None
    return build_report(findings, missing_files, coverage=coverage)


def _append_if_not_allowlisted(
    findings: list[dict[str, object]],
    finding: dict[str, object],
    allowlist: object,
) -> None:
    if is_finding_allowlisted(finding, allowlist):
        return
    findings.append(finding)


_baseline_from_report = baseline_from_report
_format_baseline_audit = format_baseline_audit
_normalize_report = normalize_report
_redact_token = redact_token
_render_token = render_token

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "CONFIG_FILENAME",
    "DEFAULT_BASELINE_FILENAME",
    "DEFAULT_IGNORE_GLOBS",
    "DEFAULT_MAX_TEXT_FILE_SIZE",
    "EntropyFinding",
    "HIGH_ENTROPY_MIN_LENGTH",
    "HIGH_ENTROPY_THRESHOLD",
    "REDACTED_TOKEN_PREFIX",
    "REQUIRED_FILES",
    "SEVERITY_RANKS",
    "SUSPICIOUS_FILENAMES",
    "apply_baseline",
    "audit_baseline",
    "baseline_from_report",
    "calculate_shannon_entropy",
    "find_high_entropy_strings",
    "format_baseline",
    "format_baseline_audit",
    "format_report",
    "format_sarif_report",
    "format_text_report",
    "has_findings",
    "has_findings_at_or_above_severity",
    "is_suspicious_filename",
    "load_baseline",
    "normalize_report",
    "prune_baseline",
    "read_text_file",
    "redact_report",
    "scan_repository",
    "update_baseline",
    "write_baseline",
]
