#!/usr/bin/env python3
"""
Usage:
  python tools/html_to_copy_extract.py --input <file.html> --output <file.md> \
    --comm-type <service|marketing> --campaign-type <service_notice|offer|...> \
    --product <internet|mobile|energy|other> --audience-stage <stage> \
    --date-sent <YYYY-MM-DD> --source <reference>

Examples:
  python tools/html_to_copy_extract.py --input intake/raw_html/example.html \
    --output kb/examples/copy_extract/service_notice-2026-01-01.md \
    --comm-type service --campaign-type service_notice --product internet \
    --audience-stage active --date-sent 2026-01-01 --source "internal ref"
"""

from __future__ import annotations

import argparse
import html
import pathlib
import re
import sys
from html.parser import HTMLParser


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip = True
        if tag in {"p", "div", "br", "li", "tr", "table", "section", "header", "footer"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip = False
        if tag in {"p", "div", "li", "tr", "table", "section", "header", "footer"}:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        text = html.unescape(data)
        self._chunks.append(text)

    def text(self) -> str:
        raw = "".join(self._chunks)
        lines = [line.strip() for line in raw.splitlines()]
        compact = "\n".join([line for line in lines if line])
        return compact


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:(?:\+?61|0)\s?[2-478])(?:[\s-]?\d){7,9}")
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
    parser = argparse.ArgumentParser(description="Convert local EDM HTML to copy extract markdown.")
    parser.add_argument("--input", required=True, help="Path to input HTML file")
    parser.add_argument("--output", required=True, help="Path to output markdown file")
    parser.add_argument("--comm-type", required=True, help="service or marketing")
    parser.add_argument("--campaign-type", required=True, help="Campaign type")
    parser.add_argument("--product", required=True, help="Product")
    parser.add_argument("--audience-stage", required=True, help="Audience stage")
    parser.add_argument("--date-sent", required=True, help="YYYY-MM-DD")
    parser.add_argument("--source", required=True, help="Internal reference (no PII)")
    parser.add_argument("--no-sanitize", action="store_true", help="Disable sanitisation")
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    output_path = pathlib.Path(args.output)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    html_text = input_path.read_text(encoding="utf-8")
    parser_instance = TextExtractor()
    parser_instance.feed(html_text)
    body_text = parser_instance.text()

    if not args.no_sanitize:
        body_text = sanitize_text(body_text)
    else:
        print("Warning: sanitisation disabled; ensure no PII is present.", file=sys.stderr)

    output = f"""# Approved EDM (Copy Extract)

**comm_type:** {args.comm_type}
**campaign_type:** {args.campaign_type}
**product:** {args.product}
**audience_stage:** {args.audience_stage}
**date_sent:** {args.date_sent}
**source:** {args.source}

## Subject
<SUBJECT_LINE_TBD>

## Preheader
<PREHEADER_TBD>

## Body (rendered text; NO PII)
{body_text}

## Notes (optional)
- CTA label: <CTA_LABEL_TBD>
- Offer / key details: <DETAILS_TBD>
- Compliance notes: <NOTES_TBD>
"""

    output_path.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
