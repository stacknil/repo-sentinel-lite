from __future__ import annotations

import re
import string
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return [
        ROOT / "README.md",
        ROOT / "RELEASE.md",
        *sorted((ROOT / "docs").rglob("*.md")),
    ]


def _slugify_heading(heading: str) -> str:
    value = heading.strip().lower()
    value = "".join(
        char for char in value if char not in string.punctuation.replace("-", "")
    )
    return "-".join(value.split())


def _anchors_for(path: Path) -> set[str]:
    anchors: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            continue
        heading = line.lstrip("#").strip()
        if heading:
            anchors.add(_slugify_heading(heading))
    return anchors


def test_local_markdown_links_resolve() -> None:
    broken_links: list[str] = []

    for markdown_path in _markdown_files():
        text = markdown_path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            raw_target = match.group(1).strip()
            if not raw_target or raw_target.startswith("#"):
                continue

            parsed = urlparse(raw_target)
            if parsed.scheme or parsed.netloc:
                continue

            link_path = unquote(parsed.path)
            target_path = (markdown_path.parent / link_path).resolve()
            try:
                target_path.relative_to(ROOT)
            except ValueError:
                broken_links.append(
                    f"{markdown_path.relative_to(ROOT)} links outside repo: "
                    f"{raw_target}"
                )
                continue

            if not target_path.exists():
                broken_links.append(
                    f"{markdown_path.relative_to(ROOT)} missing {raw_target}"
                )
                continue

            if parsed.fragment:
                anchors = _anchors_for(target_path)
                if parsed.fragment not in anchors:
                    broken_links.append(
                        f"{markdown_path.relative_to(ROOT)} missing anchor {raw_target}"
                    )

    assert broken_links == []
