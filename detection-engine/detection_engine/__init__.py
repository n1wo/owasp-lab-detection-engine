"""Local educational detection engine for lab-generated JSONL logs."""

from .models import DetectionFinding, LogEvent, ParseError, ParseResult
from .parser import load_jsonl
from .rules import (
    detect_all,
    detect_broken_access_control,
    detect_brute_force,
    detect_config_exposure,
    detect_logging_failures,
    detect_sqli_patterns,
    detect_ssrf_patterns,
    detect_weak_crypto,
    detect_xss_patterns,
)

__all__ = [
    "DetectionFinding",
    "LogEvent",
    "ParseError",
    "ParseResult",
    "detect_all",
    "detect_broken_access_control",
    "detect_brute_force",
    "detect_config_exposure",
    "detect_logging_failures",
    "detect_sqli_patterns",
    "detect_ssrf_patterns",
    "detect_weak_crypto",
    "detect_xss_patterns",
    "load_jsonl",
]

