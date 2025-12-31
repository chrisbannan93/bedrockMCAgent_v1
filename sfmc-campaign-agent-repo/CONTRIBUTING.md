# Contributing

## Goals
- Keep tools sandbox-only and Dodo-only.
- Prefer small, testable changes.
- Keep OpenAPI schemas aligned with Lambda inputs/outputs.

## What to update per tool
- `lambda/handler.py` (or equivalent)
- `openapi/<tool-name>.json`
- `docs/TOOL.md`
- `tests/*.json`
- `env.example`

## Definition of done
- Tool works with Bedrock action-group event shape AND plain HTTP event shape.
- No production references, no live send/activate actions.
- Errors are explicit and actionable (400 for bad input; 502 for upstream).
