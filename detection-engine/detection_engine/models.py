from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class LogEvent:
    """Normalized subset of a vulnerable-app JSONL log record."""

    timestamp: datetime
    event_type: str
    source_ip: str
    username: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class ParseError:
    """Non-fatal parser issue for a single JSONL line."""

    line_number: int
    reason: str
    raw_line: str


@dataclass(frozen=True)
class ParseResult:
    """Parser output with valid events plus recoverable line errors."""

    events: list[LogEvent]
    errors: list[ParseError]


@dataclass(frozen=True)
class DetectionFinding:
    """Detection result emitted by a local lab rule."""

    rule_id: str
    severity: str
    source_ip: str
    username: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    reason: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat().replace("+00:00", "Z")
        data["last_seen"] = self.last_seen.isoformat().replace("+00:00", "Z")
        return data

