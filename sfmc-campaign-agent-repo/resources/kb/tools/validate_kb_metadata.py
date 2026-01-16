#!/usr/bin/env python3
"""
Validate KB metadata sidecars in a local mirror.

Checks:
- sidecar exists for each content file
- metadataAttributes wrapper exists
- values are lowercase strings
- list values are flagged (optional strict mode)
- sidecar size <= 10KB
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

MAX_SIDECAR_BYTES = 10 * 1024


def iter_content_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name.endswith(".metadata.json"):
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate KB metadata sidecars in a local mirror.")
    parser.add_argument(
        "--root",
        default="resources/kb/kb",
        help="Root KB mirror directory (default: resources/kb/kb)",
    )
    parser.add_argument(
        "--allow-lists",
        action="store_true",
        help="Allow list-valued metadata fields (otherwise flagged).",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"Root not found: {root}", file=sys.stderr)
        return 2

    errors: list[str] = []
    warnings: list[str] = []

    for content_path in iter_content_files(root):
        sidecar_path = content_path.with_suffix(content_path.suffix + ".metadata.json")
        if not sidecar_path.exists():
            errors.append(f"Missing sidecar: {sidecar_path}")
            continue

        raw = sidecar_path.read_text(encoding="utf-8")
        if len(raw.encode("utf-8")) > MAX_SIDECAR_BYTES:
            warnings.append(f"Sidecar exceeds 10KB: {sidecar_path}")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON in {sidecar_path}: {exc}")
            continue

        attrs = payload.get("metadataAttributes")
        if not isinstance(attrs, dict):
            errors.append(f"Missing metadataAttributes in {sidecar_path}")
            continue

        for key, value in attrs.items():
            if isinstance(value, list):
                if not args.allow_lists:
                    warnings.append(f"List value for {key} in {sidecar_path}")
                for item in value:
                    if isinstance(item, str) and item != item.lower():
                        warnings.append(f"Uppercase list value for {key} in {sidecar_path}: {item}")
            elif isinstance(value, str):
                if value != value.lower():
                    warnings.append(f"Uppercase value for {key} in {sidecar_path}: {value}")
            else:
                warnings.append(
                    f"Non-string value for {key} in {sidecar_path}: {type(value).__name__}"
                )

    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    for item in warnings:
        print(f"WARN: {item}", file=sys.stderr)

    if errors:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
