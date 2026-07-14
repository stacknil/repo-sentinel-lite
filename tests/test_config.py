from __future__ import annotations

from pathlib import Path

import pytest

from repo_sentinel.config import CONFIG_FILENAME, AllowlistConfig, load_scan_config


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        (
            "entropy_threshhold = 4.2\n",
            "unknown top-level key: entropy_threshhold",
        ),
        (
            '[allowlist]\npathz = ["fixtures/**"]\n',
            "unknown allowlist key: pathz",
        ),
    ],
    ids=("top_level", "allowlist"),
)
def test_load_scan_config_rejects_unknown_keys(
    tmp_path: Path, content: str, expected_error: str
) -> None:
    (tmp_path / CONFIG_FILENAME).write_text(content, encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=rf"^\.reposentinel\.toml: {expected_error}$",
    ):
        load_scan_config(tmp_path)


def test_load_scan_config_reports_read_failure_without_absolute_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_path = tmp_path / CONFIG_FILENAME
    config_path.write_text("", encoding="utf-8")
    original_open = Path.open

    def deny_config_read(path: Path, *args: object, **kwargs: object):
        if path == config_path:
            raise PermissionError(13, "permission denied", str(path))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_config_read)

    with pytest.raises(
        ValueError,
        match=(
            r"^\.reposentinel\.toml: could not read file: permission denied$"
        ),
    ) as exc_info:
        load_scan_config(tmp_path)

    assert str(tmp_path) not in str(exc_info.value)


def test_load_scan_config_accepts_supported_legacy_aliases(tmp_path: Path) -> None:
    (tmp_path / CONFIG_FILENAME).write_text(
        "\n".join(
            [
                'suspicious_patterns = ["legacy.pem"]',
                'allowlist_paths = ["legacy/**"]',
                'allowlist_rules = ["secret.high_entropy"]',
                'allowlist_token_hashes = ["sha256:abcdef"]',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    config = load_scan_config(tmp_path)

    assert config.suspicious_filenames == ("legacy.pem",)
    assert config.allowlist == AllowlistConfig(
        paths=("legacy/**",),
        rules=("secret.high_entropy",),
        token_hashes=("abcdef",),
    )
