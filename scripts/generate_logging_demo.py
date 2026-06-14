#!/usr/bin/env python3
"""Generate localhost-only logging-failure demo activity for the detection demo."""

from __future__ import annotations

import argparse
import sys
from http.cookiejar import CookieJar
from http.client import HTTPConnection, HTTPSConnection
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener


ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEMO_ADMIN_USERNAME = "admin"
DEMO_ADMIN_PASSWORD = "admin-password"
DEMO_USER = "test-user"
DEMO_ROLE = "admin"
DEMO_USER_AGENT = "owasp-lab-logging-demo/1.0"


def validate_local_base_url(base_url: str) -> str:
    """Accept only localhost HTTP app roots and return a normalized base URL."""

    parsed = urlparse(base_url)
    if parsed.scheme != "http":
        raise ValueError("Demo target must use http:// with localhost or 127.0.0.1.")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Demo target must be localhost or 127.0.0.1 only.")
    if parsed.path not in ("", "/"):
        raise ValueError("Demo target should be the app base URL, not a third-party path.")
    return base_url.rstrip("/")


def app_is_available(base_url: str, timeout: float = 3.0) -> bool:
    """Check whether the local lab app responds successfully on /health."""

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


def send_role_change_attempt(
    base_url: str,
    user: str = DEMO_USER,
    role: str = DEMO_ROLE,
    timeout: float = 3.0,
) -> int:
    """Sign in as the local admin, send one role-change request, and return its status."""

    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    login_request = Request(
        f"{base_url}/login",
        data=urlencode(
            {"username": DEMO_ADMIN_USERNAME, "password": DEMO_ADMIN_PASSWORD}
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEMO_USER_AGENT,
        },
        method="POST",
    )
    request = Request(
        f"{base_url}/admin/role",
        data=urlencode({"user": user, "role": role}).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEMO_USER_AGENT,
        },
        method="POST",
    )
    try:
        opener.open(login_request, timeout=timeout).read()
        response = opener.open(request, timeout=timeout)
        return response.status
    except HTTPError as exc:
        return exc.code
    except URLError as exc:
        raise RuntimeError(f"Could not send demo role-change attempt: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    """Run the localhost-only logging-failure activity generator from the CLI."""

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

    try:
        status = send_role_change_attempt(base_url, timeout=args.timeout)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if status not in (200,):
        print(
            f"Unexpected logging demo status {status}. Rebuild and restart the app with: docker compose up --build",
            file=sys.stderr,
        )
        return 1

    print("Generated local logging-failure demo activity.")
    print(f"Target: {base_url}")
    print("Role change path: /admin/role")
    print(f"HTTP status observed: {status}")
    print("Next: cd detection-engine && python -m detection_engine --log-file ../logs/application.jsonl")
    return 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse command-line options for the logging-failure demo generator."""

    parser = argparse.ArgumentParser(
        description="Generate local admin role-change activity for the LOG-GAP-001 demo."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Local lab app base URL. Only http://localhost or http://127.0.0.1 are allowed.",
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
