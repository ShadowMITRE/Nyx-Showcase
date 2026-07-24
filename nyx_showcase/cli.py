"""Command-line interface for the Nyx portfolio edition."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyx-showcase",
        description="Run deterministic, offline security-text triage.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Analyze a single event.")
    source.add_argument("--file", type=Path, help="Analyze one event per non-empty line.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.text is not None:
        events = [args.text]
    else:
        try:
            events = args.file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            build_parser().error(f"could not read {args.file}: {exc}")

    report = analyze_events(events)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

