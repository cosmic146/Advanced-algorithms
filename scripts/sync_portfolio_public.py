#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "portfolio_tracker.py"
DST = ROOT / "portfolio_tracker_public.py"
SERVICE_TOKEN = "".join(("time", "2", "world"))
HOST_TOKEN = ".".join(("portfolio", SERVICE_TOKEN, "com"))
API_ENV_TOKEN = f"{SERVICE_TOKEN.upper()}_API_KEY"


def build_public_content(source: str) -> str:
    text = source

    # Global censorship replacements.
    replacements: list[tuple[str, str]] = [
        (re.escape(HOST_TOKEN), "REDACTED_HOST"),
        (re.escape(SERVICE_TOKEN), "REDACTED_SERVICE"),
        (re.escape(API_ENV_TOKEN), "AUTH_TOKEN"),
        (r"\btravis\b", "REDACTED_USER"),
        (r"api[-_ ]?key", "auth_token"),
        (r"\blogin\b", "auth"),
        (r"\bpassword\b", "secret"),
    ]

    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text, flags=re.IGNORECASE)

    # Final hard scrub: if anything slipped through, remove it outright.
    text = re.sub(re.escape(SERVICE_TOKEN), "", text, flags=re.IGNORECASE)
    text = re.sub(re.escape(HOST_TOKEN), "REDACTED_HOST", text, flags=re.IGNORECASE)

    header = (
        "# PUBLIC CENSORED MIRROR\n"
        "# This file is auto-generated from portfolio_tracker.py.\n"
        "# Do not edit manually. Edit portfolio_tracker.py instead.\n\n"
    )
    return header + text


def assert_forbidden_absent(content: str) -> None:
    lowered = content.lower()
    forbidden_tokens = [
        SERVICE_TOKEN,
        HOST_TOKEN,
        "travis",
        "api key",
        "api_key",
        "api-key",
        "login",
        "password",
        f"{SERVICE_TOKEN}_api_key",
    ]
    for token in forbidden_tokens:
        if token in lowered:
            raise RuntimeError(f"forbidden content still present: {token}")


def generate() -> tuple[bool, str]:
    if not SRC.exists():
        raise RuntimeError(f"source file missing: {SRC}")

    source = SRC.read_text(encoding="utf-8")
    public = build_public_content(source)
    assert_forbidden_absent(public)

    before = DST.read_text(encoding="utf-8") if DST.exists() else ""
    changed = before != public
    if changed:
        DST.write_text(public, encoding="utf-8")
    return changed, str(DST)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync censored public tracker file")
    parser.add_argument("--check", action="store_true", help="Fail if output is stale")
    args = parser.parse_args()

    changed, dst = generate()

    if args.check and changed:
        print(f"stale public mirror: {dst}")
        return 2

    if changed:
        print(f"updated: {dst}")
    else:
        print(f"up-to-date: {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
