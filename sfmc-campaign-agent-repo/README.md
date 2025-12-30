# SFMC Campaign Automation Agent (Dodo-only, Sandbox-only)

Region: `ap-southeast-2`

This repo contains AWS Bedrock **Action Group** tooling for a sandbox-only Salesforce Marketing Cloud (SFMC) campaign agent. Each tool is a dedicated Lambda + OpenAPI 3.0 schema and is designed to work with Bedrock Action Group invocation events **and** direct Lambda/API Gateway-style requests for local testing.

> **Guardrails**
> - Dodo only
> - Sandbox only
> - No sends, no activation/publish/stop
> - Content Builder writes allowed only under `Generate_Via_AI_Agent/...`
> - Never guess IDs; resolve them via tools

---

## Architecture overview

```
Bedrock Agent
  └─ Action Groups (OpenAPI + Lambda)
      ├─ Inspect/read tools (assets, DEs, journeys, automations)
      ├─ Draft tools (brief normalization, email composition)
      └─ Write tools (Content Builder draft asset creation)
```

**Email flow (draft-only):**
1. `sfmc-brief-normalizer` (optional) → normalize brief
2. `sfmc-asset-search` (using `/resolveFolder`) → resolve/create safe folder and return `categoryId`
3. `sfmc-email-composer` → generate email content + `emailBlueprint`
4. `sfmc-email-asset-writer` → create a draft Content Builder asset

**Orchestration:** The **Bedrock Agent** chains calls. Lambdas must **not** call other Lambdas.

---

## Tool catalog

Each tool has:
- `lambda/handler.py` (Bedrock + direct invoke support)
- `openapi/openapi.json`
- `docs/TOOL.md`
- `tests/` sample events
- `env.example`

### Enabled tools

| Tool | Purpose | Read/Write |
| --- | --- | --- |
| `sfmc-health-inspector` | Validate SFMC creds + health probes | Read-only |
| `sfmc-brief-normalizer` | Normalize campaign briefs | Read-only |
| `sfmc-category-path-inspector` | Resolve categoryId → folder path | Read-only |
| `sfmc-asset-search` | Search Content Builder assets and resolve/create folders. | Read/Write (safe-zone only for folder creation) |
| `sfmc-data-extension-inspector` | Inspect DE schema + sample rows | Read-only |
| `sfmc-automation-inspector` | Inspect Automation Studio | Read-only |
| `sfmc-journey-inspector` | Inspect Journey Builder | Read-only |
| `sfmc-email-composer` | Generate email copy + HTML + `emailBlueprint` | Read-only |
| `sfmc-email-asset-writer` | Create draft HTML Email asset from blueprint | Write (safe-zone only) |

### Not yet in Bedrock

- `sfmc-data-extension-creator`
- `sfmc-journey-draft-builder`
- `sfmc-blueprint-orchestrator`

---

## Lambda + OpenAPI alignment

Every tool is expected to:
- Accept **Bedrock Action Group** event shapes (`messageVersion`, `actionGroupInvocationInput`, `parameters`, `requestBody`)
- Accept **direct invoke** / API Gateway style events (`path`/`rawPath`, `httpMethod`, `body`)
- Return the Bedrock response wrapper when invoked by Bedrock

See `docs/CODEX_PLAYBOOK.md` for conventions.

---

## Deployment

### 1) Package a tool Lambda

Each tool is standalone. Package the folder’s `lambda/` and deploy it as a Lambda function. Example:

```
cd tools/sfmc-email-composer
zip -r ../sfmc-email-composer.zip lambda
```

### 2) Configure environment variables

Use each tool’s `env.example` as a baseline. All tools require sandbox-only credentials.

**Common variables:**
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`
- `SFMC_ALLOWED_ACCOUNT_ID` (strongly recommended)
- `SFMC_AUTH_BASE_URL` / `SFMC_REST_BASE_URL` (optional if included in secret)

### 3) IAM permissions (Lambda role)

Minimum permissions (adjust per tool):
- `secretsmanager:GetSecretValue`
- `kms:Decrypt` (if secret encrypted)
- Network egress to SFMC endpoints
- Optional: `bedrock-agent-runtime:Retrieve` (only if a tool performs explicit KB retrieval)

### 4) Create Bedrock Action Group

- Register the tool’s `openapi/openapi.json` as the Action Group schema
- Connect the Action Group to the corresponding Lambda

---

## Sample invocation payloads

### Bedrock Action Group event

```json
{
  "actionGroup": "sfmc-email-composer",
  "messageVersion": "1.0",
  "actionGroupInvocationInput": {
    "actionGroupName": "sfmc-email-composer",
    "apiPath": "/composeEmail",
    "httpMethod": "POST",
    "requestBody": {
      "content": {
        "application/json": {
          "brand": "Dodo",
          "brief": "Remind customers their bill is due soon.",
          "returnHtmlB64": true
        }
      }
    }
  }
}
```

### Direct invoke / API Gateway style

```json
{
  "path": "/composeEmail",
  "httpMethod": "POST",
  "body": "{\"brand\":\"Dodo\",\"brief\":\"Bill due reminder\"}"
}
```

---

## Guardrails & limitations

- **Sandbox-only.** Always enforce `SFMC_ALLOWED_ACCOUNT_ID`.
- **No sends or activation.** Draft/spec only.
- **No guessing IDs.** Use inspectors or `sfmc-asset-search` `/resolveFolder`.
- **Caps and clamps:** each tool enforces limits (e.g., `MAX_PAGE_SIZE`, sampling limits, path traversal caps).
- **PII masking:** sample rows are masked by default in the DE inspector.

---

## Known quirks

- SOAP property support differs by tenant/BUs; the Lambdas include fallback property sets where required.
- REST pagination caps differ across endpoints; tools clamp `pageSize` and log warnings.
- KB retrieval can be disabled in Lambdas; prefer Bedrock Agent’s native KB attachment unless explicitly required.

---

## Repo layout

```
./docs/                 # Agent instructions + architecture
./tools/<tool-name>/    # Each action group tool
```
