from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import LogEvent, ParseError, ParseResult


def load_jsonl(log_file: str | Path) -> ParseResult:
    """Load lab JSONL logs, keeping malformed lines as recoverable errors."""

    path = Path(log_file)
    events: list[LogEvent] = []
    errors: list[ParseError] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped = raw_line.strip()
            if not stripped:
                errors.append(ParseError(line_number, "blank line", raw_line.rstrip("\n")))
                continue

            try:
                record = json.loads(stripped)
                events.append(_normalize_record(record))
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                errors.append(ParseError(line_number, str(exc), raw_line.rstrip("\n")))

    return ParseResult(events=events, errors=errors)


def _normalize_record(record: dict[str, Any]) -> LogEvent:
    if not isinstance(record, dict):
        raise TypeError("log line must be a JSON object")

    timestamp = _parse_timestamp(str(record["timestamp"]))
    event_type = str(record["event_type"])
    source_ip = str(record.get("source_ip") or "unknown")
    username = str(record.get("username") or "anonymous")
    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        raw=record,
    )


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

