from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Literal, TypeAlias

from .config import normalize_path, sort_key

CoverageSkipReason: TypeAlias = Literal[
    "binary",
    "oversize",
    "symlink_policy",
    "unreadable",
    "unsupported_encoding",
]

COVERAGE_SKIP_REASONS = frozenset(
    {
        "binary",
        "oversize",
        "symlink_policy",
        "unreadable",
        "unsupported_encoding",
    }
)


def build_coverage(
    files_inspected: int,
    skipped_files: Sequence[dict[str, object]],
) -> dict[str, object]:
    if (
        isinstance(files_inspected, bool)
        or not isinstance(files_inspected, int)
        or files_inspected < 0
    ):
        raise ValueError("coverage files_inspected must be a non-negative integer")

    normalized_skips = [_normalize_skip(item) for item in skipped_files]
    normalized_skips.sort(
        key=lambda item: (*sort_key(str(item["path"])), str(item["reason"]))
    )
    reason_counts = Counter(str(item["reason"]) for item in normalized_skips)
    files_skipped = len(normalized_skips)
    return {
        "files_considered": files_inspected + files_skipped,
        "files_inspected": files_inspected,
        "files_skipped": files_skipped,
        "skipped_by_reason": dict(sorted(reason_counts.items())),
        "skipped_files": normalized_skips,
    }


def normalize_coverage(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("coverage must be an object")

    files_inspected = _non_negative_int(value.get("files_inspected"), "files_inspected")
    skipped_value = value.get("skipped_files")
    if not isinstance(skipped_value, list):
        raise ValueError("coverage skipped_files must be a list")

    normalized = build_coverage(files_inspected, skipped_value)
    for key in ("files_considered", "files_skipped"):
        supplied = _non_negative_int(value.get(key), key)
        if supplied != normalized[key]:
            raise ValueError(f"coverage {key} does not match skipped_files")

    supplied_counts = value.get("skipped_by_reason")
    if not isinstance(supplied_counts, dict):
        raise ValueError("coverage skipped_by_reason must be an object")
    normalized_counts = {
        str(reason): _non_negative_int(count, f"skipped_by_reason.{reason}")
        for reason, count in supplied_counts.items()
    }
    if normalized_counts != normalized["skipped_by_reason"]:
        raise ValueError("coverage skipped_by_reason does not match skipped_files")
    return normalized


def extract_coverage(report: object) -> dict[str, object] | None:
    if not isinstance(report, dict) or "coverage" not in report:
        return None
    return normalize_coverage(report["coverage"])


def _normalize_skip(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("coverage skipped_files entries must be objects")

    path = value.get("path")
    reason = value.get("reason")
    if not isinstance(path, str):
        raise ValueError("coverage skipped file path must be a string")
    normalized_path = normalize_path(path)
    parts = PurePosixPath(normalized_path).parts
    if (
        not parts
        or normalized_path in {"", "."}
        or normalized_path.startswith("/")
        or parts[0].endswith(":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("coverage skipped file path must be repository-relative")
    if not isinstance(reason, str) or reason not in COVERAGE_SKIP_REASONS:
        raise ValueError("coverage skipped file reason is unsupported")
    return {"path": normalized_path, "reason": reason}


def _non_negative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"coverage {field} must be a non-negative integer")
    return value


__all__ = [
    "COVERAGE_SKIP_REASONS",
    "CoverageSkipReason",
    "build_coverage",
    "extract_coverage",
    "normalize_coverage",
]
