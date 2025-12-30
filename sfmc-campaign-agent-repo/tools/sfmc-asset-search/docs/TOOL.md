# sfmc-asset-search

Read-only tool that queries SFMC Content Builder assets using:
`POST /asset/v1/content/assets/query`

This tool is designed for **sandbox-only inspection** and is safe to run frequently.

---

## What this tool does

- Search assets by **name** (contains/startsWith/endsWith/equals)
- Optionally scope results to a **folder** using `categoryId`
- Optionally filter by **asset type** (IDs and/or names)
- Returns a projected subset of fields per item

---

## Endpoint

### POST `/searchAssets`

**Request (high level)**

- `queryText` (optional): string to match against asset name
- `nameOperator` (optional): contains | startsWith | endsWith | equals  
  (legacy values also supported: like | mustContain | equal)
- `categoryId` (optional): integer (or integer string) to scope search to a folder
- `assetTypeIds` (optional): array of ints (or CSV string)
- `assetTypeNames` (optional): array of strings (or CSV string)
- `page` (default 1)
- `pageSize` (default 25, max 100)
- `fields` (optional): which fields to return per asset
- `sortBy` (default modifiedDate), `sortDir` (ASC|DESC, default DESC)

**Response**

Wrapper shape:

- `ok`: boolean
- `tool`: "asset_search"
- `input`: echo of parsed inputs (for debugging)
- `output`:
  - `count`, `page`, `pageSize`
  - `items`: list of projected assets
- `warnings`: list of strings (usually empty)

---

## Required AWS / SFMC configuration

### Secrets
One of these env vars must be set:

- `SFMC_SECRET_ARN` **or**
- `SFMC_SECRET_ID`

The secret JSON must include:

- `client_id` (or `clientId`)
- `client_secret` (or `clientSecret`)
- `auth_base_url` / `authUrl` / `auth_base_url` (or provide env override below)
- optional: `account_id` (or `accountId`)
- optional: `rest_base_url` / `restBaseUrl` (will default from auth if missing)

### Environment variables (optional overrides)

- `LOG_LEVEL` (default INFO)
- `SFMC_AUTH_BASE_URL` (overrides secret auth base)
- `SFMC_REST_BASE_URL` (overrides secret REST base)
- `SFMC_TOKEN_TIMEOUT` (default 20, clamped 5–60)
- `SFMC_API_TIMEOUT` (default 30, clamped 5–120)

---

## Guardrails / intended usage

- **Read-only**: no asset creation or folder creation.
- **No unbounded searches**: at least one of `queryText`, `categoryId`, `assetTypeIds`, `assetTypeNames` must be supplied.
- `pageSize` is clamped to **max 100** to avoid large payloads.

---

## Common usage patterns

### 1) Find emails containing “Activation”
```json
{
  "queryText": "Activation",
  "nameOperator": "contains",
  "page": 1,
  "pageSize": 25
}
