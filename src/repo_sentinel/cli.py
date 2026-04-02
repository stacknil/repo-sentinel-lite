from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .scanner import (
    DEFAULT_BASELINE_FILENAME,
    apply_baseline,
    format_baseline,
    format_report,
    format_sarif_report,
    format_text_report,
    has_findings,
    has_findings_at_or_above_severity,
    load_baseline,
    prune_baseline,
    scan_repository,
    update_baseline,
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
        help="Scan a repository and emit a deterministic report.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("json", "sarif", "text"),
        default="json",
        help="Output format. Defaults to json.",
    )
    scan_parser.add_argument(
        "--baseline",
        type=Path,
        help=(
            "Path to a baseline JSON file whose known findings should be "
            "suppressed. Defaults to .reposentinel-baseline.json in the "
            "scanned repository when present."
        ),
    )
    scan_parser.add_argument(
        "--write-baseline",
        type=Path,
        help="Path to write the current findings as a baseline JSON file.",
    )
    scan_parser.add_argument(
        "--prune-baseline",
        type=Path,
        help=(
            "Write a pruned copy of --baseline containing only entries that "
            "still match current findings."
        ),
    )
    scan_parser.add_argument(
        "--update-baseline",
        type=Path,
        help=(
            "Write a refreshed canonical baseline for the current findings "
            "state."
        ),
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 when unsuppressed findings remain.",
    )
    scan_parser.add_argument(
        "--fail-on-severity",
        choices=("error", "warning"),
        help=(
            "Return exit code 1 when unsuppressed findings remain at or above "
            "the given severity."
        ),
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        help="Write the selected output format to a file instead of stdout.",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository path to scan. Defaults to the current directory.",
    )
    scan_parser.set_defaults(handler=_run_scan)

    return parser


def _resolve_default_baseline_path(target: Path) -> Path | None:
    baseline_path = target / DEFAULT_BASELINE_FILENAME
    if baseline_path.is_file():
        return baseline_path
    return None


def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"Path is not a directory: {target}", file=sys.stderr)
        return 2

    baseline_report: dict[str, object] | None = None
    baseline_path = args.baseline or _resolve_default_baseline_path(target)
    if args.prune_baseline is not None and args.baseline is None:
        print("--prune-baseline requires --baseline", file=sys.stderr)
        return 2

    if baseline_path is not None:
        try:
            baseline_report = load_baseline(baseline_path)
        except FileNotFoundError:
            print(f"Baseline not found: {baseline_path}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Failed to read baseline {baseline_path}: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Invalid baseline {baseline_path}: {exc}", file=sys.stderr)
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

    if args.prune_baseline is not None and baseline_report is not None:
        try:
            pruned_baseline = prune_baseline(report, baseline_report)
            args.prune_baseline.write_text(
                format_baseline(pruned_baseline), encoding="utf-8"
            )
        except OSError as exc:
            print(
                f"Failed to write pruned baseline {args.prune_baseline}: {exc}",
                file=sys.stderr,
            )
            return 2

    if args.update_baseline is not None:
        try:
            refreshed_baseline = update_baseline(report, baseline_report)
            args.update_baseline.write_text(
                format_baseline(refreshed_baseline), encoding="utf-8"
            )
        except OSError as exc:
            print(
                f"Failed to write updated baseline {args.update_baseline}: {exc}",
                file=sys.stderr,
            )
            return 2

    if baseline_report is not None:
        report = apply_baseline(report, baseline_report)

    formatter = {
        "json": format_report,
        "sarif": format_sarif_report,
        "text": format_text_report,
    }[args.format]
    rendered = formatter(report)
    if args.output is None:
        print(rendered, end="")
    else:
        try:
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"Failed to write output {args.output}: {exc}", file=sys.stderr)
            return 2
    if args.fail_on_findings and has_findings(report):
        return 1
    if (
        args.fail_on_severity is not None
        and has_findings_at_or_above_severity(report, args.fail_on_severity)
    ):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
