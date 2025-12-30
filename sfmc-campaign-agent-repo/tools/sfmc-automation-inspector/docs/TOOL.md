# sfmc-automation-inspector

Read-only **sandbox** inspection tool for Salesforce Marketing Cloud (SFMC) Automation Studio.

It supports:
- Searching Automations by name
- Describing an Automation by id (with optional schedule + task summary + limited activity detail fan-out)
- Searching Query Activities and Import Activities by name
- Describing Query/Import Activities (by id; and **also** by name/customerKey in the Lambda implementation)

This tool is designed for AI-agent usage: **summary-first**, safe defaults, and hard guardrails to prevent runaway scans and payload bloat.

---

## Safety & Guardrails

- **Read-only**: uses SFMC REST GETs only.
- **Scan caps**:
  - `AUTOMATION_SEARCH_MAX_ITEMS` (default 250)
  - `QUERY_SEARCH_MAX_ITEMS` (default 250)
  - `IMPORT_SEARCH_MAX_ITEMS` (default 250)
- **Pagination clamp**:
  - `MAX_PAGE_SIZE` (default 50)
- **Activity details cap**:
  - `ACTIVITY_DETAILS_MAX_HARD_CAP` (default 25)
  - Requesting more will be clamped and returned as warnings.
- **Truncation**:
  - `SUMMARY_TEXT_TRUNCATE` (default 500) limits long strings (e.g. SQL text).
- **Optional account lock**:
  - `SFMC_ALLOWED_ACCOUNT_ID` can enforce that the Secrets Manager `account_id` matches.

---

## Authentication & Configuration

### Required env
- `SFMC_SECRET_ARN` (or `SFMC_SECRET_ID`) pointing to an AWS Secrets Manager secret containing JSON:
  - `client_id`
  - `client_secret`
  - Optional: `account_id`, `auth_base_url`, `rest_base_url`

### Optional env overrides
- `SFMC_AUTH_BASE_URL` (if you don’t store it in the secret)
- `SFMC_REST_BASE_URL` (if you don’t store it in the secret)
- If `rest_base_url` is missing, the tool will attempt to derive it from `auth_base_url` by replacing `.auth.` with `.rest.`.

---

## API Paths (Bedrock Action Group routing)

### 1) /searchAutomations
Search automations by name.

**Input**
- `queryText` (string, required)
- `nameOperator` (contains|startswith|equals, default contains)
- `statusCodes` (int[], optional) – filters returned items by `status`
- `page` (int, default 1)
- `pageSize` (int, default 25; clamped to MAX_PAGE_SIZE)
- `includeRaw` (bool, default false)

**Output**
- `items`: normalized list of automations
- `warnings`: scan-cap and clamp warnings
- If `includeRaw=true`, returns `itemsRaw` for the same slice.

---

### 2) /describeAutomation
Describe an automation by id.

**Input**
- `id` (string, required) – SFMC automation REST id
- `includeSchedule` (bool, default false)
- `includeTaskSummary` (bool, default true)
- `includeActivityDetails` (bool, default false)
- `activityDetailsMax` (int, default 20; clamped to ACTIVITY_DETAILS_MAX_HARD_CAP)
- `includeRaw` (bool, default false)

**Output**
- `automation`: normalized header
- `schedule`: normalized schedule object when available (else null + warning)
- `taskSummary`: list of tasks (seq, name, type, object ids)
- `activityDetails`: optional fan-out details for *query/import* tasks only
- `warnings`: list of warnings, including resolution failures and clamping

**Notes**
- If SFMC returns **404** for the automation id, the tool returns a **200** with `ok:false` and `error:"AUTOMATION_NOT_FOUND"` (so Bedrock doesn’t treat it as “API execution failed”). Use `/searchAutomations` to find the correct id.

---

### 3) /automationSummary
Convenience: one-call summary (header + schedule + tasks), optionally with activity details.

**Important behavior**
- In the Lambda implementation, `includeSchedule` defaults to **true** if omitted.
  - If you do NOT want schedule, explicitly pass `includeSchedule:false`.

**Input**
- `id` (string, required)
- `includeSchedule` (bool, default true in Lambda)
- `includeActivityDetails` (bool, default false)
- `activityDetailsMax` (int, default 20; clamped)
- `includeRaw` (bool, default false)

**Output**
Same shape as describeAutomation, but always includes task summary.

---

### 4) /searchQueryActivities
Search Query Activities by name.

**Input**
- `queryText` (string, required)
- `nameOperator` (contains|startswith|equals)
- `page`, `pageSize` (clamped)
- `includeRaw` (bool)

**Output**
- `items`: normalized query activity definitions
- `itemsRaw` if includeRaw=true

---

### 5) /describeQueryActivity
Describe a Query Activity.

**Documented (OpenAPI)**
- `id` (queryDefinitionId), required

**Implemented (Lambda)**
- You may provide **one of**:
  - `id` (queryDefinitionId)
  - `customerKey`
  - `name`
- The tool resolves the definition id via capped scans and then calls:
  - `GET /automation/v1/queries/{id}`

**Output**
- `query`: normalized details (includes truncated SQL text)
- `queryRaw` if includeRaw=true

**Resolution rules**
- If `id` looks like a GUID, tool tries it directly.
- If name-based resolution finds multiple matches (contains-fallback), it will refuse to auto-select and return warnings.

---

### 6) /searchImportActivities
Search Import Activities by name.

Same behavior as searchQueryActivities, but for:
- `GET /automation/v1/imports`

---

### 7) /describeImportActivity
Describe an Import Activity.

**Documented (OpenAPI)**
- `id` (importDefinitionId), required

**Implemented (Lambda)**
- You may provide **one of**:
  - `id`
  - `customerKey`
  - `name`

**Output**
- `import`: normalized details
- `importRaw` if includeRaw=true

---

## Normalized Fields (high level)

### automation (header)
- id, name, key
- status, statusName
- createdDate, modifiedDate
- lastRunTime, lastRunInstanceId
- scheduleStatus

### schedule (when available)
- status / scheduleStatus
- startDate/startTime, endDate/endTime
- timezone
- recurrenceType, recurrenceInterval, weeklyDays, monthly fields
- nextRunTime, lastRunTime (when exposed)

### taskSummary
- seq
- name
- type (activityType)
- activityObjectId / objectTypeId / step

### activityDetails (optional)
Only for tasks identified as **query** or **import**.
- type: "query" | "import"
- definitionId
- resolvedVia (id | name_exact | name_contains_unique | customerKey…)
- summary (normalized)
- raw (optional)

---

## Troubleshooting

- **AUTOMATION_NOT_FOUND**:
  - The id is wrong for the current MID/BU context, or it isn’t an automation REST id.
  - Use `/searchAutomations` by name to find the correct id.

- **Schedule missing**:
  - Some SFMC responses don’t expose schedule metadata. The tool attempts a list-lookup fallback, but schedule may still be unavailable.

- **Activity detail fan-out missing / ambiguous**:
  - Automation task names don’t always match Query/Import definition names.
  - Name-contains fallback only succeeds if exactly one unique match is found within the scan cap.

---

## Recommended agent usage pattern

1) Search automation by name: `/searchAutomations`
2) Pick the correct `id`
3) Get `/automationSummary` (includeActivityDetails=false first)
4) If needed: enable `includeActivityDetails=true` and keep `activityDetailsMax` small (e.g. 5–10)
