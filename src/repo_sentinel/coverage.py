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
CoverageEntryType: TypeAlias = Literal["file", "directory"]

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
    *,
    skipped_directories: Sequence[dict[str, object]] | None = None,
) -> dict[str, object]:
    if (
        isinstance(files_inspected, bool)
        or not isinstance(files_inspected, int)
        or files_inspected < 0
    ):
        raise ValueError("coverage files_inspected must be a non-negative integer")

    normalized_skips = [
        _normalize_skip(item, entry_type="file") for item in skipped_files
    ]
    normalized_skips.sort(
        key=lambda item: (*sort_key(str(item["path"])), str(item["reason"]))
    )
    reason_counts = Counter(str(item["reason"]) for item in normalized_skips)
    files_skipped = len(normalized_skips)
    coverage: dict[str, object] = {
        "files_considered": files_inspected + files_skipped,
        "files_inspected": files_inspected,
        "files_skipped": files_skipped,
        "skipped_by_reason": dict(sorted(reason_counts.items())),
        "skipped_files": normalized_skips,
    }
    if skipped_directories is not None:
        normalized_directories = [
            _normalize_skip(item, entry_type="directory")
            for item in skipped_directories
        ]
        normalized_directories.sort(
            key=lambda item: (*sort_key(str(item["path"])), str(item["reason"]))
        )
        coverage["directories_skipped"] = len(normalized_directories)
        coverage["skipped_directories"] = normalized_directories
    return coverage


def normalize_coverage(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("coverage must be an object")

    files_inspected = _non_negative_int(value.get("files_inspected"), "files_inspected")
    skipped_value = value.get("skipped_files")
    if not isinstance(skipped_value, list):
        raise ValueError("coverage skipped_files must be a list")

    has_directory_coverage = (
        "directories_skipped" in value or "skipped_directories" in value
    )
    directory_value: list[object] | None = None
    if has_directory_coverage:
        supplied_directories = value.get("skipped_directories")
        if not isinstance(supplied_directories, list):
            raise ValueError("coverage skipped_directories must be a list")
        directory_value = supplied_directories

    normalized = build_coverage(
        files_inspected,
        skipped_value,
        skipped_directories=directory_value,
    )
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
    if has_directory_coverage:
        supplied_directory_count = _non_negative_int(
            value.get("directories_skipped"), "directories_skipped"
        )
        if supplied_directory_count != normalized["directories_skipped"]:
            raise ValueError(
                "coverage directories_skipped does not match skipped_directories"
            )
    return normalized


def extract_coverage(report: object) -> dict[str, object] | None:
    if not isinstance(report, dict) or "coverage" not in report:
        return None
    return normalize_coverage(report["coverage"])


def _normalize_skip(
    value: object,
    *,
    entry_type: CoverageEntryType,
) -> dict[str, str]:
    collection_name = (
        "skipped_files" if entry_type == "file" else "skipped_directories"
    )
    if not isinstance(value, dict):
        raise ValueError(f"coverage {collection_name} entries must be objects")

    path = value.get("path")
    reason = value.get("reason")
    if not isinstance(path, str):
        raise ValueError(f"coverage skipped {entry_type} path must be a string")
    normalized_path = normalize_path(path)
    parts = PurePosixPath(normalized_path).parts
    if (
        not parts
        or normalized_path in {"", "."}
        or normalized_path.startswith("/")
        or parts[0].endswith(":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(
            f"coverage skipped {entry_type} path must be repository-relative"
        )
    if not isinstance(reason, str) or reason not in COVERAGE_SKIP_REASONS:
        raise ValueError(f"coverage skipped {entry_type} reason is unsupported")
    if entry_type == "directory" and reason != "symlink_policy":
        raise ValueError(
            "coverage skipped directory reason must be symlink_policy"
        )
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
