#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener


ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEMO_USERNAME = "test-user"
DEMO_PASSWORD = "wrong-local-demo-password"
DEMO_SUCCESS_PASSWORD = "lab-password"
DEMO_USER_AGENT = "owasp-lab-demo/1.0"


@dataclass(frozen=True)
class LoginAttempt:
    username: str
    password: str
    expected_success: bool


class NoRedirectHandler:
    """Keep login_success visible as a 302 instead of following /dashboard."""

    def http_error_302(self, req, fp, code, msg, headers):  # noqa: N802
        return fp

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def validate_local_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http":
        raise ValueError("Demo target must use http:// with localhost or 127.0.0.1.")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Demo target must be localhost or 127.0.0.1 only.")
    if parsed.path not in ("", "/"):
        raise ValueError("Demo target should be the app base URL, not a third-party path.")
    return base_url.rstrip("/")


def build_demo_attempts(include_success: bool = True) -> list[LoginAttempt]:
    attempts = [
        LoginAttempt(DEMO_USERNAME, DEMO_PASSWORD, expected_success=False)
        for _ in range(5)
    ]
    if include_success:
        attempts.append(LoginAttempt(DEMO_USERNAME, DEMO_SUCCESS_PASSWORD, expected_success=True))
    return attempts


def app_is_available(base_url: str, timeout: float = 3.0) -> bool:
    parsed = urlparse(base_url)
    connection_cls = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        connection = connection_cls(parsed.hostname, port, timeout=timeout)
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        return response.status == 200
    except OSError:
        return False
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass


def send_login_attempts(base_url: str, attempts: list[LoginAttempt], timeout: float = 3.0) -> list[int]:
    opener = build_opener(NoRedirectHandler)
    statuses: list[int] = []
    login_url = f"{base_url}/login"

    for attempt in attempts:
        data = urlencode({"username": attempt.username, "password": attempt.password}).encode("utf-8")
        request = Request(
            login_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": DEMO_USER_AGENT,
            },
            method="POST",
        )
        try:
            response = opener.open(request, timeout=timeout)
            statuses.append(response.status)
        except URLError as exc:
            raise RuntimeError(f"Could not send demo login attempt: {exc}") from exc

    return statuses


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        base_url = validate_local_base_url(args.base_url)
    except ValueError as exc:
        print(f"Refusing to run demo: {exc}", file=sys.stderr)
        return 2

    if not app_is_available(base_url, timeout=args.timeout):
        print(
            "Local lab app is not reachable. Start it first with: docker compose up --build",
            file=sys.stderr,
        )
        return 1

    attempts = build_demo_attempts(include_success=not args.no_success)
    try:
        statuses = send_login_attempts(base_url, attempts, timeout=args.timeout)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    failed_count = sum(1 for attempt in attempts if not attempt.expected_success)
    success_count = sum(1 for attempt in attempts if attempt.expected_success)
    print("Generated local login demo activity.")
    print(f"Target: {base_url}")
    print(f"Failed attempts: {failed_count}")
    print(f"Successful attempts: {success_count}")
    print(f"HTTP statuses observed: {', '.join(str(status) for status in statuses)}")
    print("Next: cd detection-engine && python -m detection_engine --log-file ../logs/application.jsonl")
    return 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate local login activity for the AUTH-BRUTE-FORCE-001 demo."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Local lab app base URL. Only http://localhost or http://127.0.0.1 are allowed.",
    )
    parser.add_argument(
        "--no-success",
        action="store_true",
        help="Only generate failed login attempts.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Request timeout in seconds.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())

