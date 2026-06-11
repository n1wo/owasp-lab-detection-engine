"""Local educational detection engine for lab-generated JSONL logs."""

from .models import DetectionFinding, LogEvent, ParseError, ParseResult
from .parser import load_jsonl
from .rules import detect_all, detect_brute_force, detect_sqli_patterns

__all__ = [
    "DetectionFinding",
    "LogEvent",
    "ParseError",
    "ParseResult",
    "detect_all",
    "detect_brute_force",
    "detect_sqli_patterns",
    "load_jsonl",
]

