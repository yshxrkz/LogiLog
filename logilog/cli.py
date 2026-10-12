"""Command-line entry point: argument parsing and wiring the pieces together.

Pipeline:  read file -> parse_lines() -> analyze() -> render_text()/render_json()
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .detectors import SEVERITY_ORDER, Config, analyze
from .parser import parse_lines
from .report import render_json, render_text


def build_arg_parser() -> argparse.ArgumentParser:
    defaults = Config()
    p = argparse.ArgumentParser(
        prog="logilog",
        description="Scan an SSH auth.log for brute force, odd-hour logins, "
                    "and successful logins following repeated failures.",
    )
    p.add_argument("logfile", help="path to auth.log, or '-' to read stdin")
    p.add_argument("--json", action="store_true", help="output JSON instead of a text report")
    p.add_argument("--year", type=int,
                   help="year for syslog timestamps, which omit it (default: current year)")
    p.add_argument("--threshold", type=int, default=defaults.failure_threshold,
                   help="failures from one IP within the window to flag brute force "
                        f"(default {defaults.failure_threshold})")
    p.add_argument("--window", type=int, default=defaults.window_minutes,
                   help=f"sliding window in minutes (default {defaults.window_minutes})")
    p.add_argument("--success-after", type=int, default=defaults.success_after_failures,
                   help="failures before a success to flag a likely compromise "
                        f"(default {defaults.success_after_failures})")
    p.add_argument("--work-start", type=int, default=defaults.work_start_hour,
                   help=f"start of normal hours, 0-23 (default {defaults.work_start_hour})")
    p.add_argument("--work-end", type=int, default=defaults.work_end_hour,
                   help=f"end of normal hours, 0-23 (default {defaults.work_end_hour})")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit with status 1 if any finding is at or above this severity "
                        "(useful in cron jobs / CI)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not (0 <= args.work_start <= 23 and 0 <= args.work_end <= 23):
        print("error: --work-start/--work-end must be between 0 and 23", file=sys.stderr)
        return 2

    config = Config(
        failure_threshold=args.threshold,
        window_minutes=args.window,
        work_start_hour=args.work_start,
        work_end_hour=args.work_end,
        success_after_failures=args.success_after,
    )

    try:
        if args.logfile == "-":
            events = list(parse_lines(sys.stdin, args.year))
        else:
            # errors="replace": logs can contain junk bytes from attackers
            # sending garbage usernames; never crash on a bad byte.
            with open(args.logfile, encoding="utf-8", errors="replace") as fh:
                events = list(parse_lines(fh, args.year))
    except OSError as exc:
        print(f"error: cannot read {args.logfile}: {exc.strerror}", file=sys.stderr)
        return 2

    findings = analyze(events, config)
    source = "stdin" if args.logfile == "-" else args.logfile
    render = render_json if args.json else render_text
    print(render(findings, events, source))

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
