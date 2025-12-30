# sfmc-blueprint-orchestrator

## What this tool does
Creates a **structured SFMC campaign blueprint** (plan) from a brief / normalized brief.
**Read-only / no-write tool**: it does NOT create assets, journeys, automations, or data extensions. It only outputs a blueprint JSON that downstream tools can execute.

## When to use
- After `sfmc-brief-normalizer` produces a normalized brief
- Before “builder” tools (email composer, asset writer, DE schema designer/creator, journey creator, automation creator)

## Guardrails
- Blueprint-only: never calls SFMC write APIs.
- Sandbox-only: all suggested folder paths default under `Generate_Via_AI_Agent/...`.
- Hard caps (env-driven): max assets / DEs / journeys / automations to avoid runaway output.
- No guessing of SFMC IDs. Output is names/keys/folder paths only.

## API Endpoints (Bedrock Action Group)
### POST /generateBlueprint
Input: campaign brief (messy or normalized) + optional channel constraints.
Output: structured blueprint: assets, data model, journey outline, automation outline, dependencies, and execution order.

### POST /validateBlueprint
Input: a previously generated blueprint JSON.
Output: validation results (missing required fields, cap violations, unsafe folder paths, etc.).

## Input schema (high-level)
generateBlueprint:
- brief (string) OR normalizedBrief (object/string)
- campaignName (string, optional)
- channels (array, optional): ["email","sms","push","directmail"]
- constraints (object, optional): timing, segments, exclusions, legal, etc.
- includeRationale (boolean, optional): include reasoning notes in blueprint

validateBlueprint:
- blueprint (object) required

## Output schema (high-level)
{
  ok: true,
  tool: "blueprint_orchestrator_generate",
  input: { ... },
  output: {
    schemaVersion,
    campaign: { name, objective, audience, offer, timing },
    folders: { root, emails, journeys, automations, dataExtensions },
    assets: [{ type, name, folderPath, subject, preheader, copyBrief, audienceRule }],
    dataExtensions: [{ name, customerKey, folderPath, fields:[{name,type,isPrimaryKey,isNullable}] }],
    journeys: [{ name, folderPath, entrySourceHint, steps:[...] }],
    automations: [{ name, folderPath, scheduleHint, steps:[{type,name,hint}] }],
    executionPlan: [{ step, tool, description }]
  },
  warnings: []
}

## Suggested downstream execution order
1) folder-resolver (if you enforce folder IDs at build time)
2) DE schema designer → DE creator
3) query/import designers (if needed)
4) journey draft creator
5) automation draft creator
6) email composer → email asset writer

## Example (Bedrock)
- apiPath: /generateBlueprint
- body: { "brief": "..." }

## Notes
This tool should be deterministic and conservative. Prefer returning fewer, higher-confidence blueprint items over exhaustive guessing.

Note that the `/validateBlueprint` endpoint returns the tool name `blueprint_orchestrator_validate`.
