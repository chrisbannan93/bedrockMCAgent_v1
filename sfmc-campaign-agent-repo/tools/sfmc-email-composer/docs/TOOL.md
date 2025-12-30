# sfmc-email-composer

Dodo-only, sandbox-only email drafting tool for Salesforce Marketing Cloud (SFMC).

This tool:
1) Composes a Dodo-branded email draft (subject, preheader, HTML) using optional Bedrock Knowledge Base retrieval (RAG) + a Bedrock model.
2) Emits a stable `emailBlueprint` payload for downstream tools (e.g., `sfmc-email-asset-writer`).

**Region:** ap-southeast-2 (Sydney)

---

## Scope & guardrails

- **Sandbox only.** Never use production BUs or production credentials.
- **Dodo only.** Requests for other brands must be rejected.
- **Draft only.** This tool does not send, schedule, trigger, publish, or activate anything.
- **No folderPath support.** Folder resolution/creation is handled by `sfmc-folder-resolver`.  
  You must obtain a `categoryId` first, then call `createEmailAsset`.

### Sandbox enforcement (recommended)
Set `SFMC_ALLOWED_ACCOUNT_ID` to the sandbox MID/account_id. The Lambda will refuse secrets whose `account_id` does not match.

---

## Operations

### 1) POST /composeEmail

Generates:
- `subject`
- `preheader`
- `html` (raw HTML or base64 depending on `returnHtmlB64`)
- plus `ragSources`, `warnings`, and an `emailBlueprint` object for asset creation

`emailBlueprint` includes (at minimum):
- `name`, `folderPath`, `assetTypeName`
- `subject`, `preheader`, `htmlContent`
- optional `textContent`, `htmlContentB64`, and warnings

#### Required
- `brand`: must be `Dodo` (case-insensitive accepted)
- Either:
  - `brief` (string), OR
  - `normalizedBrief` (object)

#### Optional inputs (common)
- `tone`
- `ctaText` (or alias `cta`)
- `ctaUrl`
- `emailGoal`
- `audienceSummary`
- `requiredLinks` (array)
- `personalizationTokens` (array)
- `requiredBlocks` (array)

#### RAG behavior
One of:
- Provide `ragContext` (array of strings or `{sourceUri, excerpt}` objects). If valid, it is used **instead of** KB retrieval.
- Otherwise, if `useKnowledgeBase=true`, the tool retrieves from the KB ID in `EMAIL_STYLE_KB_ID` (or override with `kbId`).

The tool **rejects** `ragContext` entries that look like non-style metadata (reflection/XML/etc.), and falls back to KB retrieval.

#### Output HTML mode
- If `returnHtmlB64=true`, response `html` will be base64 and `htmlIsB64=true`.
- If `returnHtmlB64=false`, response `html` will be plain HTML and `htmlIsB64=false`.

---

### 2) POST /createEmailAsset (legacy)

Creates a **draft** HTML Email asset in Content Builder. New flows should use `sfmc-email-asset-writer`.

#### Required
- `brand`: must be `Dodo`
- `name`: asset name
- `categoryId`: folder/category id (must be >= 1)  
  **Must come from `sfmc-folder-resolver`**
- `subject`
- `preheader` (required even if empty string)
- One of:
  - `htmlContentB64` (preferred), OR
  - `htmlContent` (raw)

#### Notes
- Asset type is fixed to `htmlemail` (id `208`).
- The response includes `assetId` for internal chaining only. Avoid echoing IDs in conversational output.

---

## Environment variables

### Required (for /createEmailAsset)
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`  
  Secrets Manager JSON must include:
  - `client_id` / `client_secret` (or `clientId` / `clientSecret`)
  - `account_id` (recommended; required if `SFMC_ALLOWED_ACCOUNT_ID` is set)
  - Optional base URLs:
    - `auth_base_url` / `authBaseUrl` / `auth_url` / `authUrl`
    - `rest_base_url` / `restBaseUrl` / `rest_url` / `restUrl`
- `SFMC_ALLOWED_ACCOUNT_ID` (strongly recommended)

### Optional (compose/RAG/model)
- `EMAIL_STYLE_KB_ID` (KB used when `useKnowledgeBase=true` and no `kbId` provided)
- `BEDROCK_WRITER_MODEL_ID` (default: `anthropic.claude-3-sonnet-20240229-v1:0`)

### Optional (timeouts/limits)
- `LOG_LEVEL` (default: INFO)
- `SFMC_TOKEN_TIMEOUT` (default: 20; clamped 5–60)
- `SFMC_API_TIMEOUT` (default: 30; clamped 5–120)
- `MAX_HTML_CHARS` (default: 200000; clamped 10000–1000000)

---

## Local testing checklist (recommended)

Add a small `tests/` folder per tool with:
- `event-bedrock-composeEmail.json`
- `event-bedrock-createEmailAsset.json`
- `event-http-composeEmail.json`
- `event-http-createEmailAsset.json`

And a simple runner script:
- loads env vars
- invokes `lambda_handler(event, None)`
- prints the response body

---

## Expected upstream tool chain

Typical sequence for “create a draft email asset”:
1) `sfmc-brief-normalizer` (if brief is messy)
2) `sfmc-folder-resolver` → returns `categoryId`
3) `sfmc-email-composer` `/composeEmail` (prefer `returnHtmlB64=true`)
4) `sfmc-email-asset-writer` `/writeEmailAsset` using `emailBlueprint` + `categoryId`

---

## Definition of done

- `/composeEmail` succeeds with and without KB retrieval.
- `/createEmailAsset` succeeds in sandbox with a known safe `categoryId`.
- Passing `folderPath` to `/createEmailAsset` returns a clear 400 telling callers to use folder-resolver.
- If `SFMC_ALLOWED_ACCOUNT_ID` is set, secrets with mismatched `account_id` are rejected.
- Tool returns helpful `warnings` instead of failing when RAG retrieval is unavailable.
