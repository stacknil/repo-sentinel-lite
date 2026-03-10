from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .scanner import (
    apply_baseline,
    format_report,
    load_baseline,
    scan_repository,
    write_baseline,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-sentinel",
        description=(
            "Scan repositories for common suspicious files and "
            "secrets-like strings."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a repository and emit a deterministic JSON report.",
    )
    scan_parser.add_argument(
        "--baseline",
        type=Path,
        help="Path to a baseline JSON file whose known findings should be suppressed.",
    )
    scan_parser.add_argument(
        "--write-baseline",
        type=Path,
        help="Path to write the current findings as a baseline JSON file.",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository path to scan. Defaults to the current directory.",
    )
    scan_parser.set_defaults(handler=_run_scan)

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"Path is not a directory: {target}", file=sys.stderr)
        return 2

    baseline_report: dict[str, object] | None = None
    if args.baseline is not None:
        try:
            baseline_report = load_baseline(args.baseline)
        except FileNotFoundError:
            print(f"Baseline not found: {args.baseline}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Failed to read baseline {args.baseline}: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Invalid baseline {args.baseline}: {exc}", file=sys.stderr)
            return 2

    report = scan_repository(target)

    if args.write_baseline is not None:
        try:
            write_baseline(args.write_baseline, report)
        except OSError as exc:
            print(
                f"Failed to write baseline {args.write_baseline}: {exc}",
                file=sys.stderr,
            )
            return 2

    if baseline_report is not None:
        report = apply_baseline(report, baseline_report)

    print(format_report(report), end="")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
