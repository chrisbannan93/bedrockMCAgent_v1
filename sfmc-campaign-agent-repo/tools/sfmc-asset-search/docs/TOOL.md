# sfmc-asset-search

A tool for interacting with SFMC Content Builder assets. It supports two primary functions:
1.  **Searching for assets**: `POST /searchAssets` (Read-only)
2.  **Resolving and creating folders**: `POST /resolveFolder` (Write-capable)

This tool is designed for **sandbox-only** environments.

---

## What this tool does

-   Search assets by **name** (contains/startsWith/endsWith/equals)
-   Optionally scope results to a **folder** using `categoryId` or `folderPath`.
-   Optionally filter by **asset type** (IDs and/or names).
-   Resolve a given `folderPath` to its `categoryId`.
-   Create folders in Content Builder if they do not already exist.
-   Returns a projected subset of fields for asset searches.

---

## Endpoints

### POST `/searchAssets` (Read-only)

**Request (high level)**

-   `queryText` (optional): string to match against asset name
-   `nameOperator` (optional): contains | startsWith | endsWith | equals
-   `folderPath` (optional): string path like `Journeys/NBN`. The tool will resolve this to a `categoryId` for the search.
-   `categoryId` (optional): integer (or integer string) to scope search to a folder. Overrides `folderPath` if both are provided.
-   `assetTypeIds` (optional): array of ints (or CSV string)
-   `assetTypeNames` (optional): array of strings (or CSV string)
-   `page` (default 1)
-   `pageSize` (default 25, max 100)
-   `fields` (optional): which fields to return per asset
-   `sortBy` (default modifiedDate), `sortDir` (ASC|DESC, default DESC)

**Response**

-   `ok`: boolean
-   `tool`: "asset_search"
-   `output`:
    -   `count`, `page`, `pageSize`
    -   `items`: list of projected assets

### POST `/resolveFolder` (Write-capable)

**Request (high level)**

-   `folderPath`: string path like `Journeys/NBN/Activation`
-   `createIfMissing` (optional, default `true`): If `true`, the tool will create any missing folders in the path.
-   `assetFamily` (optional, default `content-builder`): The SFMC asset family.

**Response**

-   `ok`: boolean
-   `tool`: "folder_resolver"
-   `output`:
    -   `categoryId`: The integer ID of the final folder in the path.
    -   `created`: Boolean indicating if any folders were created.
    -   `normalizedPath`: An array of the folder path segments.
    -   `assetFamily`: The asset family used.

---

## Required AWS / SFMC configuration

### Secrets
One of these env vars must be set:

-   `SFMC_SECRET_ARN` **or**
-   `SFMC_SECRET_ID`

The secret JSON must include:

-   `client_id` (or `clientId`)
-   `client_secret` (or `clientSecret`)
-   `auth_base_url` (or equivalent)
-   optional: `account_id`
-   optional: `rest_base_url`

### Environment variables (optional overrides)

-   `LOG_LEVEL` (default INFO)
-   `SFMC_AUTH_BASE_URL`
-   `SFMC_REST_BASE_URL`

---

## Guardrails / intended usage

-   **Read/Write**: The `/searchAssets` endpoint is read-only. The `/resolveFolder` endpoint can create folders, which is a write operation.
-   Folder creation is restricted to the "safe zone" as defined by SFMC permissions.
-   `pageSize` for searches is clamped to **max 100**.

---

## Common usage patterns

### 1) Find emails containing “Activation”
```json
{
  "apiPath": "/searchAssets",
  "httpMethod": "POST",
  "requestBody": {
    "content": {
      "application/json": {
        "body": "{\\"queryText\\":\\"Activation\\",\\"assetTypeNames\\":[\\"htmlemail\\"]}"
      }
    }
  }
}
```

### 2) Get the ID for a folder, creating it if it doesn't exist
```json
{
  "apiPath": "/resolveFolder",
  "httpMethod": "POST",
  "requestBody": {
    "content": {
      "application/json": {
        "body": "{\\"folderPath\\":\\"My Project/Subfolder\\"}"
      }
    }
  }
}
```
