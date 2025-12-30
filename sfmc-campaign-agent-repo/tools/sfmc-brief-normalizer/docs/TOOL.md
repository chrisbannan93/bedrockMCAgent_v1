# sfmc-brief-normalizer

Normalizes a messy SFMC campaign brief into structured JSON for downstream tools (blueprint orchestrator, DE/journey builders).

## Endpoints
- POST `/normalizeBrief`
- GET `/health`

## Inputs (normalizeBrief)
- `rawBrief` (string, required)
- `context` (object, optional)

## Output
- `ok` boolean
- `output.normalizedBrief` object
- `warnings` array of strings

## Notes / guardrails
- Always returns valid JSON.
- If model output is invalid/unparseable, returns a safe fallback structure and warnings.
- No SFMC access, no side effects.
