# Metadata Sidecar Schema (Bedrock KB)

## Overview
Each KB document may include a sidecar file named `<filename>.metadata.json` stored next to the source file. Sidecars enable filtering and targeted retrieval. Bedrock expects metadata under a top-level `metadataAttributes` object.

- Keep sidecars under 10KB.
- Use lower-case strings for stable filtering.
- Use a single string value per field to align with strict equality filtering in retrieval. If you need
  multi-scope values, confirm your KB retrieval filter supports list matching before using arrays.
- Only include fields that apply to the file type.

## Base Schema (Minimal)
```json
{
  "metadataAttributes": {
    "brand": "dodo",
    "channel": "edm",
    "doc_type": "rule",
    "campaign_type": "service_notice",
    "product": "internet",
    "module_type": "cta",
    "format": "markdown"
  }
}
```

## Multi-scope guidance
If a document is valid for multiple scopes, prefer the most general applicable value (for example, `other`) so it can be matched by strict equality filters. If you do store arrays for multi-scope values, ensure your KB retrieval filters handle list matching (otherwise prefer `other`).

## Validation helper
Run `resources/kb/tools/validate_kb_metadata.py` to check for missing sidecars, missing
`metadataAttributes`, uppercase values, and list-valued metadata (unless `--allow-lists`
is set).

## Field Definitions
- **brand**: Always `dodo`.
- **channel**: Content channel, typically `edm` for email.
- **doc_type**: `rule` | `approved_example` | `module`.
- **campaign_type**: `service_notice` | `offer` | `price_change` | `billing` | `outage` | `winback` | `other`. Prefer a single string.
- **product**: `internet` | `mobile` | `energy` | `other`. Prefer a single string.
- **module_type** (modules only): `cta` | `support_block` | `pricing_panel` | `info_block` | `footer` | `legal` | `logo` | `other`.
- **format**: `markdown` | `html_snippet`.

## Examples
### Rule document
```json
{
  "metadataAttributes": {
    "brand": "dodo",
    "channel": "edm",
    "doc_type": "rule",
    "campaign_type": "other",
    "product": "other",
    "format": "markdown"
  }
}
```

### Module snippet
```json
{
  "metadataAttributes": {
    "brand": "dodo",
    "channel": "edm",
    "doc_type": "module",
    "campaign_type": "other",
    "product": "other",
    "module_type": "cta",
    "format": "html_snippet"
  }
}
```

### Approved example
```json
{
  "metadataAttributes": {
    "brand": "dodo",
    "channel": "edm",
    "doc_type": "approved_example",
    "campaign_type": "service_notice",
    "product": "internet",
    "format": "markdown"
  }
}
```
