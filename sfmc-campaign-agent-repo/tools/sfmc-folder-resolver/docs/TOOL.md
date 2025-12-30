# sfmc-folder-resolver

Action group description (<=200 chars):
Resolve/create SFMC Content Builder folders under Generate_Via_AI_Agent safe root (sandbox only) and return categoryId for downstream draft asset creation.

## Purpose
Resolve an SFMC Content Builder folder path (Categories API) **under a configured safe root** and return the resolved `categoryId`. Optionally creates missing folder segments.

This tool is a dependency for any “create draft asset” capability (emails, templates, etc.) because SFMC asset creation requires a valid `categoryId`.

## Operations
### POST /resolveFolder  (operationId: resolveFolder)
**Inputs**
- `folderPath` (string, required)
  - Path to resolve under the safe root. Example: `Generate_Via_AI_Agent/Emails/AgentTests`
- `createIfMissing` (boolean, optional, default: `true`)
  - If `true`, missing segments are created.
  - If `false`, missing segments produce a `404` with `FOLDER_NOT_FOUND`.
- `assetFamily` (string, optional, default: `content-builder`)
  - Only `content-builder` is supported.

**Success Output (200)**
- `ok: true`
- `output.categoryId` (int): resolved folder CategoryId
- `output.created` (bool): whether any segments were created
- `output.normalizedPath` (string[]): final path segments used under the safe root
- `warnings` (string[]): usually empty

**Failure Outputs**
- `400 BAD_REQUEST`: missing or invalid `folderPath`/unsupported `assetFamily`
- `404 FOLDER_NOT_FOUND`: when `createIfMissing=false` and a segment doesn’t exist
- `500`: config/auth/network/SFMC API failures

## Safety & guardrails
- **Sandbox-only intent**: this tool should only be wired to a sandbox SFMC BU.
- **Safe-root enforced by config**:
  - The Lambda always resolves paths relative to `CONTENT_ROOT_PARENT_ID` (a CategoryId).
  - This prevents resolving/creating folders outside the configured safe tree.
- **Do not echo SFMC IDs in chat**:
  - The tool returns `categoryId` for chaining, but the assistant should not repeat IDs back to users.

## Configuration (Lambda environment variables)

### Required
- `CONTENT_ROOT_PARENT_ID`
  - CategoryId of the **Generate_Via_AI_Agent** root folder in the sandbox BU.

### Strongly recommended
- `CONTENT_ROOT_NAME` (e.g. `Generate_Via_AI_Agent`)
  - If the incoming `folderPath` starts with this segment, the Lambda strips it to avoid nesting the root inside itself.
  - Example: If `CONTENT_ROOT_NAME=Generate_Via_AI_Agent` and request is `Generate_Via_AI_Agent/Emails/AgentTests`,
    it resolves `Emails/AgentTests` under `CONTENT_ROOT_PARENT_ID`.

### SFMC auth config
Preferred:
- `SFMC_SECRET_ID` = Secrets Manager secret id/arn containing SFMC creds + auth url

Fallback (env creds):
- `SFMC_CLIENT_ID`
- `SFMC_CLIENT_SECRET`
- `SFMC_AUTH_URL` (or `auth_url`)
- `SFMC_REST_BASE_URL` (optional; if absent, uses token response `rest_instance_url`)
- `SFMC_ACCOUNT_ID` (optional)

### Optional debugging
- `LOG_LEVEL` (default INFO)
- `DEBUG_EVENT` = true/false
- `DEBUG_EVENT_MAX_CHARS` (default 1500)

## Secrets Manager JSON shape
The secret should be valid JSON and can contain any of these keys:
- `client_id` or `SFMC_CLIENT_ID`
- `client_secret` or `SFMC_CLIENT_SECRET`
- `auth_base_url` or `auth_url`
- `rest_base_url` (optional)
- `account_id` (optional)

## Bedrock event compatibility
The Lambda is designed to accept multiple Bedrock invocation shapes:
- `event.actionGroupInvocationInput.parameters` (list of `{name,value}` objects)
- `event.actionGroupInvocationInput.requestBody.content.application/json...` (object/body/list/string)
- Direct keys for local testing

The response is wrapped in the Bedrock Action Group response envelope:
- `messageVersion`
- `response.actionGroup`
- `response.apiPath`
- `response.httpMethod`
- `response.httpStatusCode`
- `response.responseBody.application/json.body`

## Example requests

### Resolve and create (default)
```json
{
  "folderPath": "Generate_Via_AI_Agent/Emails/AgentTests"
}
