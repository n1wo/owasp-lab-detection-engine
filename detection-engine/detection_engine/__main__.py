"""Command-line entry point for running local lab detection rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parser import load_jsonl
from .rules import detect_brute_force


def main(argv: list[str] | None = None) -> int:
    """Run the detection CLI and print findings for a selected log file."""

    args = _parse_args(argv)
    result = load_jsonl(args.log_file)
    findings = detect_brute_force(result.events)

    if args.json:
        payload = {
            "findings": [finding.to_dict() for finding in findings],
            "parse_errors": [
                {
                    "line_number": error.line_number,
                    "reason": error.reason,
                    "raw_line": error.raw_line,
                }
                for error in result.errors
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(findings)
        for error in result.errors:
            print(
                f"Warning: skipped line {error.line_number}: {error.reason}",
                file=sys.stderr,
            )

    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse command-line options for the local detection engine."""

    parser = argparse.ArgumentParser(
        description="Run local lab detection rules against vulnerable-app JSONL logs."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("../logs/application.jsonl"),
        help="Path to local vulnerable-app JSONL log file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings and parse errors as JSON.",
    )
    return parser.parse_args(argv)


def _print_human(findings) -> None:
    """Print detection findings in a compact human-readable format."""

    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print(f"{finding.rule_id} [{finding.severity}]")
        print(f"  source_ip: {finding.source_ip}")
        print(f"  username: {finding.username}")
        print(f"  event_count: {finding.event_count}")
        print(f"  first_seen: {finding.first_seen.isoformat().replace('+00:00', 'Z')}")
        print(f"  last_seen: {finding.last_seen.isoformat().replace('+00:00', 'Z')}")
        print(f"  reason: {finding.reason}")


if __name__ == "__main__":
    raise SystemExit(main())

