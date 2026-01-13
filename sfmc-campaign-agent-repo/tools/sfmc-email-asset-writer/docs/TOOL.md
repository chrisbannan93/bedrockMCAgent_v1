# sfmc-email-asset-writer

Dodo-only, sandbox-only tool for creating **draft** HTML Email assets in SFMC Content Builder.

This tool is designed to take the `emailBlueprint` output from `sfmc-email-composer` (KB RAG required) plus a `categoryId` returned by `sfmc-asset-search` `/resolveFolder`.

---

## Scope & guardrails

- **Sandbox only.** Never use production BUs or production credentials.
- **Dodo only.** Requests for other brands must be rejected.
- **Draft only.** No sends, scheduling, activation, or publish actions.
- **No folderPath resolution.** You must call `sfmc-asset-search` `/resolveFolder` to obtain a `categoryId`.

### Sandbox enforcement (recommended)
Set `SFMC_ALLOWED_ACCOUNT_ID` to the sandbox MID/account_id. The Lambda will refuse secrets whose `account_id` does not match.

---

## Operation

### POST /writeEmailAsset

Creates a **draft** HTML Email asset in Content Builder.

#### Required
- `categoryId`: folder/category id (must be >= 1) from `sfmc-asset-search` `/resolveFolder`
- Either:
  - `emailBlueprint` (from `sfmc-email-composer`, KB RAG required), OR
  - direct fields: `name`, `subject`, `preheader`, and `htmlContent` or `htmlContentB64`

#### Notes
- Asset type is fixed to `htmlemail` (id `208`).
- The response includes `assetId` for internal chaining only. Avoid echoing IDs in conversational output.

---

## Environment variables

### Required
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`
  Secrets Manager JSON must include:
  - `client_id` / `client_secret` (or `clientId` / `clientSecret`)
  - `account_id` (recommended; required if `SFMC_ALLOWED_ACCOUNT_ID` is set)
  - Optional base URLs:
    - `auth_base_url` / `authBaseUrl` / `auth_url` / `authUrl`
    - `rest_base_url` / `restBaseUrl` / `rest_url` / `restUrl`
- `SFMC_ALLOWED_ACCOUNT_ID` (strongly recommended)

### Optional
- `LOG_LEVEL` (default: INFO)
- `SFMC_TOKEN_TIMEOUT` (default: 20; clamped 5–60)
- `SFMC_API_TIMEOUT` (default: 30; clamped 5–120)
- `MAX_HTML_CHARS` (default: 200000; clamped 10000–1000000)

---

## Expected upstream tool chain

Typical sequence for “create a draft email asset”:
1) `sfmc-brief-normalizer` (if brief is messy)
2) `sfmc-email-composer` `/composeEmail` (prefer `returnHtmlB64=true`, KB RAG required)
3) `sfmc-asset-search` `/resolveFolder` → returns `categoryId` (requested or default folder)
4) `sfmc-email-asset-writer` `/writeEmailAsset` using `categoryId` + subject + preheader + htmlContentB64 (from composer/emailBlueprint)

---

## Definition of done

- `/writeEmailAsset` succeeds in sandbox with a known safe `categoryId`.
- Passing `folderPath` without `categoryId` returns a clear 400 telling callers to use `sfmc-asset-search` `/resolveFolder`.
- If `SFMC_ALLOWED_ACCOUNT_ID` is set, secrets with mismatched `account_id` are rejected.
