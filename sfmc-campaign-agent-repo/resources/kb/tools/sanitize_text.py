#!/usr/bin/env python3
"""
Usage:
  python tools/sanitize_text.py --input <path> --output <path>

Examples:
  python tools/sanitize_text.py --input intake/raw.txt --output intake/raw.sanitized.txt
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?:(?:\+?61|0)\s?[2-478])(?:[\s-]?\d){7,9}"
)
ACCOUNT_RE = re.compile(r"\b(?:account|acct|acc)\s*#?\s*\d{6,12}\b", re.IGNORECASE)
ADDRESS_RE = re.compile(
    r"\b\d+\s+[A-Za-z0-9\s]+\s(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct)\b",
    re.IGNORECASE,
)


def sanitize_text(text: str) -> str:
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = PHONE_RE.sub("<MOBILE>", text)
    text = ACCOUNT_RE.sub("<ACCOUNT_ID>", text)
    text = ADDRESS_RE.sub("<ADDRESS>", text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact PII-like patterns in text files.")
    parser.add_argument("--input", required=True, help="Path to input text file")
    parser.add_argument("--output", required=True, help="Path to output text file")
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    output_path = pathlib.Path(args.output)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    text = input_path.read_text(encoding="utf-8")
    sanitized = sanitize_text(text)
    output_path.write_text(sanitized, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
