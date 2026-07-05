from __future__ import annotations

import fnmatch
import hashlib
import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath

REQUIRED_FILES = ("README.md", "LICENSE", ".gitignore")
SUSPICIOUS_FILENAMES = (".env", "*.pem", "*.key", "id_rsa", "*.kdbx")
HIGH_ENTROPY_THRESHOLD = 4.0
HIGH_ENTROPY_MIN_LENGTH = 20
DEFAULT_MAX_TEXT_FILE_SIZE = 1_048_576
CONFIG_FILENAME = ".reposentinel.toml"
DEFAULT_BASELINE_FILENAME = ".reposentinel-baseline.json"
DEFAULT_IGNORE_GLOBS = (
    DEFAULT_BASELINE_FILENAME,
    "%TEMP%",
    "*.egg-info",
    ".coverage",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".venv-*",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "dist-*",
    "htmlcov",
    "node_modules",
    "venv",
)
ALLOW_COMMENT_PATTERN = re.compile(
    r"repo-sentinel:\s*allow(?:\s+(?P<rules>[A-Za-z0-9_.\-, ]+))?",
    re.IGNORECASE,
)
_DIRECTORY_CHILD_GLOB_SUFFIXES = ("/**/*", "/**", "/*")


@dataclass(frozen=True)
class AllowlistConfig:
    paths: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    token_hashes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanConfig:
    ignore_globs: tuple[str, ...] = DEFAULT_IGNORE_GLOBS
    entropy_threshold: float = HIGH_ENTROPY_THRESHOLD
    max_text_file_size: int = DEFAULT_MAX_TEXT_FILE_SIZE
    suspicious_filenames: tuple[str, ...] = SUSPICIOUS_FILENAMES
    required_files: tuple[str, ...] = REQUIRED_FILES
    allowlist: AllowlistConfig = AllowlistConfig()


def load_scan_config(root: Path) -> ScanConfig:
    config_path = root / CONFIG_FILENAME
    if not config_path.is_file():
        return ScanConfig()

    try:
        with config_path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except OSError:
        return ScanConfig()

    return ScanConfig(
        ignore_globs=_merge_default_ignore_globs(
            _get_string_list(data, "ignore_globs", ())
        ),
        entropy_threshold=_get_float(
            data, "entropy_threshold", HIGH_ENTROPY_THRESHOLD
        ),
        max_text_file_size=_get_int(
            data, "max_text_file_size", DEFAULT_MAX_TEXT_FILE_SIZE
        ),
        suspicious_filenames=_get_suspicious_filenames(
            data, SUSPICIOUS_FILENAMES
        ),
        required_files=_get_string_list(data, "required_files", REQUIRED_FILES),
        allowlist=_get_allowlist_config(data),
    )


def is_suspicious_filename(
    path: str | Path | PurePath,
    patterns: Sequence[str] = SUSPICIOUS_FILENAMES,
) -> bool:
    return matches_globs(normalize_path(path), patterns)


def normalize_path(path: str | Path | PurePath) -> str:
    return PurePosixPath(_normalize_logical_path_string(str(path))).as_posix()


def normalize_path_string(path: str) -> str:
    return normalize_path(path)


def matches_globs(path: str, patterns: Sequence[str]) -> bool:
    normalized_path = normalize_path(path)
    filename = PurePosixPath(normalized_path).name
    folded_path = normalized_path.casefold()
    folded_filename = filename.casefold()

    for pattern in patterns:
        folded_pattern = normalize_path(pattern).casefold()
        if fnmatch.fnmatchcase(folded_path, folded_pattern):
            return True
        if fnmatch.fnmatchcase(folded_filename, folded_pattern):
            return True

    return False


def matches_directory_ignore(path: str, patterns: Sequence[str]) -> bool:
    normalized_path = normalize_path(path)
    folded_path = normalized_path.casefold()
    if matches_globs(normalized_path, patterns):
        return True

    for pattern in patterns:
        folded_pattern = normalize_path(pattern).casefold()
        for suffix in _DIRECTORY_CHILD_GLOB_SUFFIXES:
            directory_root = folded_pattern[: -len(suffix)]
            if folded_pattern.endswith(suffix) and folded_path == directory_root:
                return True

    return False


def sort_key(value: str) -> tuple[str, str]:
    return (value.casefold(), value)


def relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def finding_path(finding: dict[str, object]) -> str | None:
    path = finding.get("path")
    if isinstance(path, str):
        return normalize_path(path)
    file_path = finding.get("file")
    if isinstance(file_path, str):
        return normalize_path(file_path)
    return None


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_finding_allowlisted(
    finding: dict[str, object], allowlist: AllowlistConfig
) -> bool:
    path = finding_path(finding)
    if path is not None and matches_globs(path, allowlist.paths):
        return True

    kind = str(finding.get("kind", ""))
    rule_id = str(finding.get("rule_id", ""))
    if kind.casefold() in _folded_values(allowlist.rules):
        return True
    if rule_id.casefold() in _folded_values(allowlist.rules):
        return True

    token = finding.get("token")
    if isinstance(token, str) and _token_hash_is_allowlisted(
        token_sha256(token), allowlist.token_hashes
    ):
        return True

    return False


def comment_allows_rule(line: str, *, kind: str, rule_id: str) -> bool:
    match = ALLOW_COMMENT_PATTERN.search(line)
    if match is None:
        return False

    rule_text = match.group("rules")
    if rule_text is None:
        return True

    allowed_rules = {
        value.strip().casefold()
        for value in rule_text.split(",")
        if value.strip()
    }
    return kind.casefold() in allowed_rules or rule_id.casefold() in allowed_rules


def scoped_comment_allows_rule(
    lines: Sequence[str], line_number: int, *, kind: str, rule_id: str
) -> bool:
    indexes = [line_number - 1, line_number - 2]
    return any(
        0 <= index < len(lines)
        and comment_allows_rule(lines[index], kind=kind, rule_id=rule_id)
        for index in indexes
    )


def _normalize_logical_path_string(path: str) -> str:
    return path.replace("\\", "/")


def _get_float(data: dict[str, object], key: str, default: float) -> float:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{key} must be a float")
    return float(value)


def _get_int(data: dict[str, object], key: str, default: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if value < 0:
        raise ValueError(f"{key} must be non-negative")
    return value


def _get_string_list(
    data: dict[str, object], key: str, default: Sequence[str]
) -> tuple[str, ...]:
    value = data.get(key)
    if value is None:
        return tuple(default)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return tuple(value)


def _get_suspicious_filenames(
    data: dict[str, object], default: Sequence[str]
) -> tuple[str, ...]:
    if "suspicious_filenames" in data:
        return _get_string_list(data, "suspicious_filenames", default)
    return _get_string_list(data, "suspicious_patterns", default)


def _get_allowlist_config(data: dict[str, object]) -> AllowlistConfig:
    allowlist_value = data.get("allowlist", {})
    if allowlist_value is None:
        allowlist_value = {}
    if not isinstance(allowlist_value, dict):
        raise ValueError("allowlist must be a table")

    paths = _get_string_list(
        allowlist_value, "paths", _get_string_list(data, "allowlist_paths", ())
    )
    rules = _get_string_list(
        allowlist_value, "rules", _get_string_list(data, "allowlist_rules", ())
    )
    token_hashes = _get_string_list(
        allowlist_value,
        "token_hashes",
        _get_string_list(data, "allowlist_token_hashes", ()),
    )
    return AllowlistConfig(
        paths=tuple(normalize_path(path) for path in paths),
        rules=tuple(rule.casefold() for rule in rules),
        token_hashes=tuple(_normalize_token_hash(value) for value in token_hashes),
    )


def _merge_default_ignore_globs(
    ignore_globs: Sequence[str],
) -> tuple[str, ...]:
    ordered_patterns = [*DEFAULT_IGNORE_GLOBS, *ignore_globs]
    return tuple(dict.fromkeys(ordered_patterns))


def _folded_values(values: Sequence[str]) -> set[str]:
    return {value.casefold() for value in values}


def _normalize_token_hash(value: str) -> str:
    normalized = value.removeprefix("sha256:").casefold()
    if not normalized:
        raise ValueError("allowlist token_hashes entries must not be empty")
    if not re.fullmatch(r"[0-9a-f]+", normalized):
        raise ValueError("allowlist token_hashes entries must be SHA-256 hex")
    return normalized


def _token_hash_is_allowlisted(digest: str, allowed_hashes: Sequence[str]) -> bool:
    folded_digest = digest.casefold()
    return any(
        folded_digest == allowed_hash or folded_digest.startswith(allowed_hash)
        for allowed_hash in allowed_hashes
    )
