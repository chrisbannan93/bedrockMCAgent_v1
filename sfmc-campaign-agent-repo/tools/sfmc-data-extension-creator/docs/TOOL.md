# sfmc-data-extension-creator

Read/write **sandbox** tool to:
- validate a Data Extension spec (no SFMC call)
- search Data Extensions by name
- describe a Data Extension (by customerKey) incl. fields
- create a Data Extension (SOAP CreateRequest)

This tool is designed for Bedrock Agents (Action Groups) and direct Lambda tests.

---

## API Paths

- `POST /validateDataExtensionSpec`
- `POST /searchDataExtensions`
- `POST /describeDataExtension`
- `POST /createDataExtension`

Aliases also supported in Lambda:
- `/validateDE`
- `/searchDEs`
- `/describeDE`
- `/createDE`

---

## Key Behaviour (Safety + Defaults)

### Sandbox Guardrails
- If `SFMC_ALLOWED_ACCOUNT_ID` is set, the secret `account_id` must match.
- Optional: set `REQUIRE_SANDBOX_FLAG=true` and `SFMC_ENVIRONMENT=sandbox`.

### Folder Safety
- If `SAFE_DATAEXT_FOLDER_ROOT` is set, any `folderPath` must start with that prefix.
- Blocks path traversal: rejects `..`.

### Dry Run
- Default `dryRun=true` (configurable via `DEFAULT_DRY_RUN`).
- To actually create: pass `dryRun=false`.

### Overwrite
- If a Data Extension exists for the same `customerKey`, creation returns **409**.
- No update/overwrite behaviour is implemented (intentionally).

### Field Normalisation
- Enforces caps: `MAX_FIELDS`, name lengths.
- Normalises common type aliases to SFMC types:
  - string -> Text
  - integer/int -> Number
  - bool -> Boolean
  - datetime/date -> Date
  - decimal -> Decimal
- PrimaryKey implies Required (forced with warning).

---

## Inputs

### FieldSpec
- `name` (required)
- `type` (required): Text, Number, Date, Boolean, Decimal, EmailAddress, Phone, Locale
- `maxLength` (Text only)
- `precision`, `scale` (Decimal only)
- `isRequired` (default false)
- `isPrimaryKey` (default false)
- `defaultValue` (optional)

### CreateDataExtensionRequest
- `name` (required)
- `customerKey` (required)
- `fields` (required array)
- `folderId` (preferred) OR `folderPath` (optional, resolved via SOAP DataFolder traversal)
- `allowCreateMissingFolders` (default from env)
- `isSendable` + `sendableField` + `sendableSubscriberField` (optional)
- `dryRun` (default true)
- `includeRaw` (default false) -> includes SOAP raw response when create/search fails or requested.

---

## Example (Bedrock-style)

Create (dry-run):
```json
{
  "name": "AI_Test_DE_01",
  "customerKey": "AI_Test_DE_01",
  "folderPath": "Generate_Via_AI_Agent/DataExtensions/AgentTests",
  "dryRun": true,
  "fields": [
    {"name":"SubscriberKey","type":"Text","maxLength":50,"isPrimaryKey":true},
    {"name":"EmailAddress","type":"EmailAddress","isRequired":false},
    {"name":"CreatedAt","type":"Date"}
  ]
}
