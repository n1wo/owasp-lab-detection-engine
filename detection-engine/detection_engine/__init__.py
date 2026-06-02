"""Local educational detection engine for lab-generated JSONL logs."""

from .models import DetectionFinding, LogEvent, ParseError, ParseResult
from .parser import load_jsonl
from .rules import detect_brute_force

__all__ = [
    "DetectionFinding",
    "LogEvent",
    "ParseError",
    "ParseResult",
    "detect_brute_force",
    "load_jsonl",
]

