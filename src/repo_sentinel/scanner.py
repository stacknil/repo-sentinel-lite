from __future__ import annotations

import codecs
import fnmatch
import json
import math
import os
import re
import tomllib
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath, PurePosixPath

REQUIRED_FILES = ("README.md", "LICENSE", ".gitignore")
SUSPICIOUS_FILENAMES = (".env", "*.pem", "*.key", "id_rsa", "*.kdbx")
HIGH_ENTROPY_THRESHOLD = 4.0
HIGH_ENTROPY_MIN_LENGTH = 20
TEXT_SAMPLE_SIZE = 8192
CONFIG_FILENAME = ".reposentinel.toml"
BASELINE_SCHEMA_VERSION = 1
TOKEN_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{{{HIGH_ENTROPY_MIN_LENGTH},}}"
    r"(?:={1,2})?)(?![A-Za-z0-9+/_=-])"
)

_TEXT_CONTROL_BYTES = {7, 8, 9, 10, 12, 13, 27}
_BYTE_ORDER_MARKS = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF32_LE,
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


@dataclass(frozen=True)
class ScanConfig:
    ignore_globs: tuple[str, ...] = ()
    entropy_threshold: float = HIGH_ENTROPY_THRESHOLD
    suspicious_filenames: tuple[str, ...] = SUSPICIOUS_FILENAMES
    required_files: tuple[str, ...] = REQUIRED_FILES


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


def is_suspicious_filename(
    path: str | Path | PurePath,
    patterns: Sequence[str] = SUSPICIOUS_FILENAMES,
) -> bool:
    return _matches_globs(_normalize_path(path), patterns)


def scan_repository(root: Path) -> dict[str, object]:
    resolved_root = root.resolve()
    config = _load_scan_config(resolved_root)
    suspicious_files: list[str] = []
    entropy_findings: list[EntropyFinding] = []

    for path in _iter_files(resolved_root, config.ignore_globs):
        relative_path = _relative_path(path, resolved_root)

        if is_suspicious_filename(relative_path, config.suspicious_filenames):
            suspicious_files.append(relative_path)

        text = _read_text_file(path)
        if text is None:
            continue

        entropy_findings.extend(
            find_high_entropy_strings(
                relative_path, text, threshold=config.entropy_threshold
            )
        )

    suspicious_files.sort(key=_sort_key)
    entropy_findings.sort(
        key=lambda finding: (_sort_key(finding.file), finding.line, finding.token)
    )

    return {
        "high_entropy_findings": [
            finding.to_dict() for finding in entropy_findings
        ],
        "missing_files": _detect_missing_files(resolved_root, config.required_files),
        "suspicious_files": suspicious_files,
    }


def load_baseline(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline is not valid JSON: {exc.msg}") from exc

    if _looks_like_legacy_report(data):
        return _baseline_from_report(_normalize_report(data))

    return _normalize_baseline(data)


def write_baseline(path: Path, report: dict[str, object]) -> None:
    path.write_text(format_baseline(_baseline_from_report(report)), encoding="utf-8")


def apply_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    current_entropy, current_missing, current_suspicious = _extract_report_components(
        report
    )
    baseline_finding_keys = frozenset(
        _baseline_finding_identity(finding)
        for finding in _extract_baseline_findings(baseline)
    )

    return _report_from_components(
        [
            finding
            for finding in current_entropy
            if _baseline_finding_identity(_entropy_baseline_finding(finding))
            not in baseline_finding_keys
        ],
        {
            path: is_missing
            and _baseline_finding_identity(_missing_file_baseline_finding(path))
            not in baseline_finding_keys
            for path, is_missing in current_missing.items()
        },
        [
            path
            for path in current_suspicious
            if _baseline_finding_identity(_suspicious_file_baseline_finding(path))
            not in baseline_finding_keys
        ],
    )


def format_report(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def format_text_report(report: dict[str, object]) -> str:
    entropy_findings, missing_files, suspicious_files = _extract_report_components(
        report
    )
    missing_paths = [path for path, is_missing in missing_files.items() if is_missing]
    lines: list[str] = []

    if suspicious_files:
        lines.append(f"Suspicious files ({len(suspicious_files)}):")
        lines.extend(f"- {path}" for path in suspicious_files)

    if missing_paths:
        if lines:
            lines.append("")
        lines.append(f"Missing required files ({len(missing_paths)}):")
        lines.extend(f"- {path}" for path in missing_paths)

    if entropy_findings:
        if lines:
            lines.append("")
        lines.append(f"High-entropy findings ({len(entropy_findings)}):")
        lines.extend(
            (
                f"- {finding.file}:{finding.line} "
                f"entropy={finding.entropy} token={finding.token}"
            )
            for finding in entropy_findings
        )

    if not lines:
        return "No findings.\n"

    return "\n".join(lines) + "\n"


def has_findings(report: dict[str, object]) -> bool:
    entropy_findings, missing_files, suspicious_files = _extract_report_components(
        report
    )
    return bool(
        entropy_findings or suspicious_files or any(missing_files.values())
    )


def format_baseline(baseline: dict[str, object]) -> str:
    return json.dumps(_normalize_baseline(baseline), indent=2, sort_keys=True) + "\n"


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


def _load_scan_config(root: Path) -> ScanConfig:
    config_path = root / CONFIG_FILENAME
    if not config_path.is_file():
        return ScanConfig()

    try:
        with config_path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except OSError:
        return ScanConfig()

    return ScanConfig(
        ignore_globs=_get_string_list(data, "ignore_globs", ()),
        entropy_threshold=_get_float(
            data, "entropy_threshold", HIGH_ENTROPY_THRESHOLD
        ),
        suspicious_filenames=_get_suspicious_filenames(
            data, SUSPICIOUS_FILENAMES
        ),
        required_files=_get_string_list(data, "required_files", REQUIRED_FILES),
    )


def _detect_missing_files(root: Path, required_files: Sequence[str]) -> dict[str, bool]:
    present_files = {
        _relative_path(path, root).casefold() for path in _iter_files(root, ())
    }
    return {
        _normalize_path(filename): _normalize_path(filename).casefold()
        not in present_files
        for filename in required_files
    }


def _iter_files(root: Path, ignore_globs: Sequence[str]) -> list[Path]:
    paths: list[Path] = []

    for current_root, dirnames, filenames in os.walk(root, topdown=True):
        current_dir = Path(current_root)
        dirnames[:] = [
            name
            for name in dirnames
            if name.casefold() != ".git"
            and not _matches_globs(
                _relative_path(current_dir / name, root), ignore_globs
            )
        ]
        dirnames.sort(key=_sort_key)

        filenames = [
            name
            for name in filenames
            if not _matches_globs(
                _relative_path(current_dir / name, root), ignore_globs
            )
        ]
        filenames.sort(key=_sort_key)

        for filename in filenames:
            paths.append(current_dir / filename)

    return paths


def _read_text_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if not _is_probably_text(data[:TEXT_SAMPLE_SIZE]):
        return None

    for encoding in ("utf-8", "utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue

    return None


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


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _normalize_logical_path_string(path: str) -> str:
    return path.replace("\\", "/")


def _normalize_path(path: str | Path | PurePath) -> str:
    return PurePosixPath(_normalize_logical_path_string(str(path))).as_posix()


def _matches_globs(path: str, patterns: Sequence[str]) -> bool:
    normalized_path = _normalize_path(path)
    filename = PurePosixPath(normalized_path).name
    folded_path = normalized_path.casefold()
    folded_filename = filename.casefold()

    for pattern in patterns:
        folded_pattern = _normalize_path(pattern).casefold()
        if fnmatch.fnmatchcase(folded_path, folded_pattern):
            return True
        if fnmatch.fnmatchcase(folded_filename, folded_pattern):
            return True

    return False


def _get_float(data: dict[str, object], key: str, default: float) -> float:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{key} must be a float")
    return float(value)


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


def _sort_key(value: str) -> tuple[str, str]:
    return (value.casefold(), value)


def _baseline_from_report(report: dict[str, object]) -> dict[str, object]:
    entropy_findings, missing_files, suspicious_files = _extract_report_components(
        report
    )
    findings = [_entropy_baseline_finding(finding) for finding in entropy_findings]
    findings.extend(
        _missing_file_baseline_finding(path)
        for path, is_missing in missing_files.items()
        if is_missing
    )
    findings.extend(
        _suspicious_file_baseline_finding(path) for path in suspicious_files
    )
    findings.sort(key=_baseline_finding_sort_key)

    return {
        "findings": findings,
        "generated_at": _generate_baseline_timestamp(),
        "schema_version": BASELINE_SCHEMA_VERSION,
    }


def _generate_baseline_timestamp() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    )


def _looks_like_legacy_report(value: object) -> bool:
    return isinstance(value, dict) and any(
        key in value
        for key in ("high_entropy_findings", "missing_files", "suspicious_files")
    )


def _normalize_baseline(baseline: object) -> dict[str, object]:
    if not isinstance(baseline, dict):
        raise ValueError("baseline must be a JSON object")

    schema_version = baseline.get("schema_version")
    generated_at = baseline.get("generated_at")
    findings_value = baseline.get("findings")

    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise ValueError("baseline schema_version must be an integer")
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise ValueError(
            f"baseline schema_version must be {BASELINE_SCHEMA_VERSION}"
        )
    if not isinstance(generated_at, str):
        raise ValueError("baseline generated_at must be a string")
    if not isinstance(findings_value, list):
        raise ValueError("baseline findings must be a list")

    findings = [_coerce_baseline_finding(item) for item in findings_value]
    findings.sort(key=_baseline_finding_sort_key)

    return {
        "findings": findings,
        "generated_at": generated_at,
        "schema_version": schema_version,
    }


def _extract_baseline_findings(baseline: object) -> list[dict[str, object]]:
    normalized = _normalize_baseline(baseline)
    findings = normalized["findings"]
    if not isinstance(findings, list):
        raise ValueError("baseline findings must be a list")
    return findings


def _normalize_report(report: object) -> dict[str, object]:
    entropy_findings, missing_files, suspicious_files = _extract_report_components(
        report
    )
    return _report_from_components(
        entropy_findings, missing_files, suspicious_files
    )


def _extract_report_components(
    report: object,
) -> tuple[list[EntropyFinding], dict[str, bool], list[str]]:
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")

    return (
        _coerce_entropy_findings(report.get("high_entropy_findings", [])),
        _coerce_missing_files(report.get("missing_files", {})),
        _coerce_string_list(report.get("suspicious_files", [])),
    )


def _report_from_components(
    entropy_findings: Sequence[EntropyFinding],
    missing_files: dict[str, bool],
    suspicious_files: Sequence[str],
) -> dict[str, object]:
    return {
        "high_entropy_findings": [finding.to_dict() for finding in entropy_findings],
        "missing_files": {
            path: is_missing
            for path, is_missing in sorted(
                missing_files.items(), key=lambda item: _sort_key(item[0])
            )
        },
        "suspicious_files": list(suspicious_files),
    }


def _coerce_entropy_findings(value: object) -> list[EntropyFinding]:
    if not isinstance(value, list):
        raise ValueError("high_entropy_findings must be a list")

    findings = [_coerce_entropy_finding(item) for item in value]
    findings.sort(
        key=lambda finding: (
            _sort_key(finding.file),
            finding.line,
            finding.token,
            finding.entropy,
        )
    )
    return findings


def _coerce_entropy_finding(value: object) -> EntropyFinding:
    if not isinstance(value, dict):
        raise ValueError("high_entropy_findings entries must be objects")

    file_path = value.get("file")
    line = value.get("line")
    token = value.get("token")
    entropy = value.get("entropy")

    if not isinstance(file_path, str):
        raise ValueError("high_entropy_findings file must be a string")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ValueError("high_entropy_findings line must be a positive integer")
    if not isinstance(token, str):
        raise ValueError("high_entropy_findings token must be a string")
    if isinstance(entropy, bool) or not isinstance(entropy, int | float):
        raise ValueError("high_entropy_findings entropy must be a number")

    return EntropyFinding(
        file=_normalize_path(file_path),
        line=line,
        token=token,
        entropy=round(float(entropy), 4),
    )


def _coerce_missing_files(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("missing_files must be an object")

    normalized_items: list[tuple[str, bool]] = []
    for path, is_missing in value.items():
        if not isinstance(path, str):
            raise ValueError("missing_files keys must be strings")
        if not isinstance(is_missing, bool):
            raise ValueError("missing_files values must be booleans")
        normalized_items.append((_normalize_path(path), is_missing))

    normalized_items.sort(key=lambda item: _sort_key(item[0]))
    return dict(normalized_items)


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("suspicious_files must be a list of strings")

    normalized_values = [_normalize_path(item) for item in value]
    normalized_values.sort(key=_sort_key)
    return normalized_values


def _coerce_baseline_finding(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("baseline findings entries must be objects")

    kind = value.get("kind")
    if kind == "high_entropy":
        finding = _coerce_entropy_finding(value)
        normalized = finding.to_dict()
        normalized["kind"] = kind
        return normalized
    if kind in {"missing_file", "suspicious_file"}:
        path = value.get("path")
        if not isinstance(path, str):
            raise ValueError(f"{kind} baseline path must be a string")
        return {"kind": kind, "path": _normalize_path(path)}

    raise ValueError("baseline findings kind must be recognized")


def _baseline_finding_sort_key(finding: dict[str, object]) -> tuple[object, ...]:
    kind = finding["kind"]
    if kind == "high_entropy":
        file_key = _sort_key(_normalize_path(str(finding["file"])))
        return (
            0,
            file_key[0],
            file_key[1],
            int(finding["line"]),
            str(finding["token"]),
            float(finding["entropy"]),
        )

    path_key = _sort_key(_normalize_path(str(finding["path"])))
    return (
        1 if kind == "missing_file" else 2,
        path_key[0],
        path_key[1],
    )


def _baseline_finding_identity(finding: dict[str, object]) -> tuple[object, ...]:
    kind = str(finding["kind"])
    if kind == "high_entropy":
        return (
            kind,
            _normalize_path(str(finding["file"])),
            int(finding["line"]),
            str(finding["token"]),
            float(finding["entropy"]),
        )
    return (kind, _normalize_path(str(finding["path"])))


def _entropy_baseline_finding(finding: EntropyFinding) -> dict[str, object]:
    normalized = finding.to_dict()
    normalized["kind"] = "high_entropy"
    return normalized


def _missing_file_baseline_finding(path: str) -> dict[str, object]:
    return {"kind": "missing_file", "path": _normalize_path(path)}


def _suspicious_file_baseline_finding(path: str) -> dict[str, object]:
    return {"kind": "suspicious_file", "path": _normalize_path(path)}
