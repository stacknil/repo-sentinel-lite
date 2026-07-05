from __future__ import annotations

from .config import token_sha256

REDACTED_TOKEN_PREFIX = "<redacted:sha256:"


def render_token(token: str, reveal_secrets: bool) -> str:
    if reveal_secrets:
        return token
    return redact_token(token)


def redact_token(token: str) -> str:
    digest = token_sha256(token)
    return f"{REDACTED_TOKEN_PREFIX}{digest[:12]}>"


def redact_report(report: dict[str, object]) -> dict[str, object]:
    return _redact_tokens(report)


def redact_baseline(baseline: dict[str, object]) -> dict[str, object]:
    return _redact_tokens(baseline)


def _redact_tokens(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if key == "token" and isinstance(item, str):
                redacted[key] = redact_token(item)
            else:
                redacted[key] = _redact_tokens(item)
        return redacted
    if isinstance(value, list):
        return [_redact_tokens(item) for item in value]
    return value
