from __future__ import annotations

import codecs
import os
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import (
    matches_directory_ignore,
    matches_globs,
    normalize_path,
    relative_path,
    sort_key,
)
from .coverage import CoverageSkipReason

TEXT_SAMPLE_SIZE = 8192
_TEXT_CONTROL_BYTES = {7, 8, 9, 10, 12, 13, 27}
_BYTE_ORDER_MARKS = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF32_LE,
)
_TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "cp1252")


@dataclass(frozen=True, slots=True)
class TextReadSuccess:
    text: str


@dataclass(frozen=True, slots=True)
class TextReadSkipped:
    reason: CoverageSkipReason


TextReadResult = TextReadSuccess | TextReadSkipped


def iter_files(
    root: Path,
    ignore_globs: Sequence[str],
    *,
    changed_paths: Iterable[str] | None = None,
) -> Iterator[Path]:
    if changed_paths is not None:
        yield from _iter_changed_files(root, ignore_globs, changed_paths)
        return

    for current_root, dirnames, filenames in os.walk(root, topdown=True):
        current_dir = Path(current_root)
        dirnames[:] = [
            name
            for name in dirnames
            if name.casefold() != ".git"
            and not matches_directory_ignore(
                relative_path(current_dir / name, root), ignore_globs
            )
        ]
        dirnames.sort(key=sort_key)

        filenames = [
            name
            for name in filenames
            if not matches_globs(
                relative_path(current_dir / name, root), ignore_globs
            )
        ]
        filenames.sort(key=sort_key)

        for filename in filenames:
            yield current_dir / filename


def read_text_file(path: Path, max_text_file_size: int) -> str | None:
    result = inspect_text_file(path, max_text_file_size)
    if isinstance(result, TextReadSkipped):
        return None
    return result.text


def inspect_text_file(path: Path, max_text_file_size: int) -> TextReadResult:
    try:
        if path.is_symlink():
            return TextReadSkipped("symlink_policy")
        if path.stat().st_size > max_text_file_size:
            return TextReadSkipped("oversize")
    except OSError:
        return TextReadSkipped("unreadable")

    try:
        data = path.read_bytes()
    except OSError:
        return TextReadSkipped("unreadable")

    if not _is_probably_text(data[:TEXT_SAMPLE_SIZE]):
        return TextReadSkipped("binary")

    for encoding in _TEXT_ENCODINGS:
        try:
            return TextReadSuccess(data.decode(encoding))
        except UnicodeDecodeError:
            continue

    return TextReadSkipped("unsupported_encoding")


def _iter_changed_files(
    root: Path,
    ignore_globs: Sequence[str],
    changed_paths: Iterable[str],
) -> Iterator[Path]:
    seen: set[str] = set()
    normalized_paths = sorted(
        {
            normalize_path(path)
            for path in changed_paths
            if normalize_path(path) not in {"", "."}
        },
        key=sort_key,
    )
    for normalized_path in normalized_paths:
        candidate = _candidate_changed_file(root, normalized_path)
        if candidate is None:
            continue
        relative = relative_path(candidate, root)
        if relative in seen or matches_globs(relative, ignore_globs):
            continue
        seen.add(relative)
        yield candidate


def _candidate_changed_file(root: Path, normalized_path: str) -> Path | None:
    parts = PurePosixPath(normalized_path).parts
    if (
        not parts
        or parts[0] == "/"
        or any(part in {"", ".", ".."} for part in parts)
    ):
        return None

    candidate = root.joinpath(*parts)
    try:
        resolved_candidate = candidate.resolve(strict=False)
        resolved_candidate.relative_to(root)
    except (OSError, ValueError):
        return None

    if not candidate.is_file():
        return None
    return candidate


def _is_probably_text(sample: bytes) -> bool:
    if not sample:
        return True
    if any(sample.startswith(bom) for bom in _BYTE_ORDER_MARKS):
        return True
    if b"\x00" in sample:
        return False

    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass

    control_bytes = sum(
        1 for byte in sample if byte < 32 and byte not in _TEXT_CONTROL_BYTES
    )
    return (control_bytes / len(sample)) < 0.30
