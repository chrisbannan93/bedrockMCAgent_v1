#!/usr/bin/env python3
"""
Usage:
  python tools/add_metadata_sidecars.py --config <mapping.json>

Config format (JSON):
{
  "entries": [
    {
      "path": "kb/rules/00_dodo_voice_principles.md",
      "metadata": {
        "metadataAttributes": {
          "brand": "dodo",
          "channel": "edm",
          "doc_type": "rule",
          "campaign_type": "other",
          "product": "other",
          "format": "markdown"
        }
      }
    }
  ]
}

Examples:
  python tools/add_metadata_sidecars.py --config tools/metadata_map.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Create metadata sidecars from a JSON mapping.")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without writing files")
    args = parser.parse_args()

    config_path = pathlib.Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 1

    config = json.loads(config_path.read_text(encoding="utf-8"))
    entries = config.get("entries", [])

    if not entries:
        print("No entries found in config.", file=sys.stderr)
        return 1

    for entry in entries:
        target_path = pathlib.Path(entry.get("path", ""))
        metadata = entry.get("metadata", {})
        if not target_path.exists():
            print(f"Skipping missing file: {target_path}", file=sys.stderr)
            continue

        if "metadataAttributes" not in metadata:
            metadata = {"metadataAttributes": metadata}

        sidecar_path = target_path.with_suffix(target_path.suffix + ".metadata.json")
        content = json.dumps(metadata, indent=2, sort_keys=True)
        if len(content.encode("utf-8")) > 10 * 1024:
            print(f"Sidecar too large (>10KB): {sidecar_path}", file=sys.stderr)
            continue

        if args.dry_run:
            print(f"Would write: {sidecar_path}")
        else:
            sidecar_path.write_text(content + "\n", encoding="utf-8")
            print(f"Wrote: {sidecar_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
