# sfmc-data-extension-inspector

Sandbox, **read-only** SFMC inspection tool for:
- Searching Data Extensions (SOAP)
- Describing a Data Extension (metadata + fields + optional folder path) (SOAP)
- Sampling Data Extension rows (REST Data API) with PII masking (REST)
- Searching/listing Data Folders (SOAP DataFolder)
- Resolving a folderId to its full path (SOAP traversal)

This tool is intended for AWS Bedrock Agents (Action Groups) and also supports direct Lambda tests.

---

## Safety / Guardrails

- **Read-only**: no asset creation, no DE writes, no sends, no journey activation.
- **Account allowlist**: if `SFMC_ALLOWED_ACCOUNT_ID` is set, the OAuth secret must include matching `account_id` / `accountId`.
- **Hard caps**:
  - `MAX_PAGE_SIZE` clamps paging.
  - `DE_SEARCH_MAX_ITEMS` caps DataExtension search (SOAP).
  - `DATAFOLDER_SEARCH_MAX_ITEMS` caps DataFolder search/list (SOAP).
  - `DE_SAMPLE_MAX_ROWS` caps sample rows returned from REST.
  - `DATAFOLDER_INCLUDE_PATH_CAP` caps how many returned folders can have paths computed when `includePath=true`.
- **PII masking** in sample rows enabled by default via `DE_SAMPLE_MASK_PII=true`.
- **Truncation** for string values in sampled rows via `DE_SAMPLE_TRUNCATE_LEN`.

---

## API Paths

### Data Extensions
- `POST /searchDataExtensions`
  - Search by `queryText` (Name like/equals/startsWith) OR exact `customerKey`.
- `POST /getDataExtension`
  - Describe by `customerKey` OR `objectId`. Optionally include fields and folder path.
- `POST /inspectDataExtension`
  - Alias of `/getDataExtension` for backward compatibility.
- `POST /sampleDataExtensionRows`
  - Sample a small set of rows by `customerKey` (REST Data API), with PII masking.

### Data Folders
- `POST /searchDataFolders`
  - Search by name or list children by `parentId`. Optional filter by `contentTypes`. Optional `includePath`.
- `POST /describeDataFolderPath`
  - Resolve a folderId to full path by traversing parents. `maxDepth` clamped to 1..100.

---

## Notes / Known Behaviors

- SOAP calls use SOAP 1.1. `SOAPAction` header is set to `Retrieve`.
- SOAP envelope keeps `<fueloauth>` un-namespaced for better tenant compatibility.
- Folder path resolution caches folder metadata and computed paths during warm Lambda reuse.
- DataExtensionField retrieval tries two filters:
  - `DataExtension.CustomerKey == customerKey`
  - fallback: `DataExtension.ObjectID == objectId`
- If a DE returns no fields but you expect fields, enable `DEBUG_SOAP=true` to inspect SOAP statuses.

---

## Example Requests

### Search DEs
```json
{
  "queryText": "Agent",
  "nameOperator": "contains",
  "page": 1,
  "pageSize": 25
}
