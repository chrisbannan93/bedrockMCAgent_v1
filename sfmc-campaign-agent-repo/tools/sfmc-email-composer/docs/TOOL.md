# sfmc-email-composer (KB RAG required)

Dodo-only, sandbox-only email drafting tool for Salesforce Marketing Cloud (SFMC).

This tool:
1) Composes a Dodo-branded email draft (subject, preheader, HTML) using Bedrock Knowledge Base retrieval (RAG required) + a Bedrock model.
2) Emits a stable `emailBlueprint` payload for downstream tools (e.g., `sfmc-email-asset-writer`).

**Region:** ap-southeast-2 (Sydney)

---

## Scope & guardrails

- **Sandbox only.** Never use production BUs or production credentials.
- **Dodo only.** Requests for other brands must be rejected.
- **Draft only.** This tool does not send, schedule, trigger, publish, or activate anything.
- **Folder resolution/creation is handled by `sfmc-asset-search` `/resolveFolder`.**  
  You must obtain a `categoryId` first, then call `sfmc-email-asset-writer`.

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
- `name`, `folderPath` (optional), `assetTypeName`
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
- `templateHtml` (string, optional) — full HTML container with a `{{BODY_HTML}}` placeholder or a Content Builder slot to inject into.
- `templateSlotKey` (string, optional) — `data-key` value for a `<div data-type="slot" ...>` placeholder if `{{BODY_HTML}}` is not present.
- `templateSlotLabel` (string, optional) — `data-label` value for a `<div data-type="slot" ...>` placeholder if `{{BODY_HTML}}` is not present.

#### RAG behavior
One of:
- Provide `ragContext` (array of strings or `{sourceUri, excerpt}` objects). If valid, it is used **instead of** KB retrieval (KB RAG requirement satisfied).
- Otherwise, `useKnowledgeBase` must be true and the tool retrieves from the KB ID in `EMAIL_STYLE_KB_ID` (or override with `kbId`).

The tool **rejects** `ragContext` entries that look like non-style metadata (reflection/XML/etc.), and falls back to KB retrieval (required).

#### Output HTML mode
- If `returnHtmlB64=true`, response `html` will be base64 and `htmlIsB64=true`.
- If `returnHtmlB64=false`, response `html` will be plain HTML and `htmlIsB64=false`.

#### Template mode (optional)
If `templateHtml` is provided:
- It must include a `{{BODY_HTML}}` placeholder.
- If no `{{BODY_HTML}}` placeholder is present, the tool will try to inject into a `<div data-type="slot">` using `templateSlotKey` (preferred) or `templateSlotLabel`.
- The model is instructed to return **body-only HTML** (no `<html>`, `<head>`, or `<body>` tags).
- The tool injects the generated body into the template and returns the final HTML.

---

## Environment variables

### Required (compose/RAG/model)
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
- `event-bedrock.json` (composeEmail)
- `event-http.json` (composeEmail)

And a simple runner script:
- loads env vars
- invokes `lambda_handler(event, None)`
- prints the response body

---

## Expected upstream tool chain

Typical sequence for “create a draft email asset”:
1) `sfmc-brief-normalizer` (if brief is messy)
2) `sfmc-email-composer` `/composeEmail` (prefer `returnHtmlB64=true`, KB RAG required)
3) `sfmc-asset-search` `/resolveFolder` → returns `categoryId` (requested or default folder)
4) `sfmc-email-asset-writer` `/writeEmailAsset` using `categoryId` + subject + preheader + htmlContentB64 (from composer/emailBlueprint)

---

## Definition of done

- `/composeEmail` uses KB retrieval (RAG required).
- If `SFMC_ALLOWED_ACCOUNT_ID` is set, secrets with mismatched `account_id` are rejected.
- Tool returns helpful `warnings` instead of failing when RAG retrieval is unavailable.
