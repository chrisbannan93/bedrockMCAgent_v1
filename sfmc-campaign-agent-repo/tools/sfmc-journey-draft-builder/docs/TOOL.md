# sfmc-journey-draft-builder

## Purpose
This tool validates a Journey Spec payload and can optionally create a **draft** Journey in SFMC. It is designed to make journey drafts nearly activation-ready by normalizing inputs, validating required configuration for common activity types, and (optionally) creating the entry event definition and the draft journey in SFMC.

## Guardrails
- **Sandbox-only**: All operations are restricted to the SFMC environment specified by `SFMC_REQUIRED_ENV` (default: `sandbox`).
- **Host allowlist (optional)**: If `SFMC_ALLOWED_HOST_SUFFIXES` is set, SFMC auth/rest hosts must match an allowed suffix.
- **Account allowlist (optional)**: If `SFMC_ALLOWED_ACCOUNT_ID` is set, the token account must match.
- **No activation/publish**: This tool can only create **draft** journeys. It cannot activate, publish, pause, or stop journeys.
- **Size/cap guardrails**: Enforces maximum triggers, activities, and total payload size.

> Note: “Dodo-only” is a **global agent policy** in this repo; it is not enforced in the Lambda code.

## Environment variables
### Required
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`: AWS Secrets Manager reference containing SFMC API credentials.
- `SFMC_ENV`: Current SFMC environment (e.g., `sandbox`). Must match `SFMC_REQUIRED_ENV`.
- `SFMC_REQUIRED_ENV`: Required SFMC environment. Defaults to `sandbox`.

### Optional
- `SFMC_ALLOWED_ACCOUNT_ID`: Restrict to a specific SFMC account ID.
- `SFMC_ALLOWED_HOST_SUFFIXES`: Comma-separated allowed host suffixes for SFMC API calls.
- `DRY_RUN_DEFAULT`: Defaults to `true`. If `true`, the tool will validate only unless `dryRun=false` is provided.
- `REST_TIMEOUT`: HTTP timeout in seconds (default: `20`).
- `MAX_TRIGGERS`: Max triggers in the Journey Spec (default: `10`).
- `MAX_ACTIVITIES`: Max activities in the Journey Spec (default: `200`).
- `MAX_SPEC_BYTES`: Max serialized Journey Spec size (default: `300000`).

## Operations

### POST `/journeydraft`
- **`operationId`**: `journeyDraftBuild`
- **Description**: Validates a Journey Spec payload. If `createInSfmc=true` and `dryRun=false`, it will attempt to create a draft journey in SFMC.

### POST `/journey-draft`
- **`operationId`**: `journeyDraftBuildAliasDash`
- **Description**: Alias for `/journeydraft`.

### POST `/draft`
- **`operationId`**: `journeyDraftBuildAlias`
- **Description**: Alias for `/journeydraft`.

### GET `/healthz`
- **`operationId`**: `healthz`
- **Description**: Validates runtime configuration and guardrails without calling SFMC.

## Input summary
You can send inputs in one of these shapes:
- **Direct invoke**: the event object *is* the params object.
- **API Gateway**: `body` contains a JSON string or object.
- **Bedrock Action Group**: `actionGroupInvocationInput.parameters` + `requestBody.content.application/json`.

### Required Journey Spec fields
At minimum: `key`, `name`, `workflowApiVersion`, `triggers`, `activities`.

### Required config for common types
- **EVENT trigger**: `configurationArguments.eventDefinitionKey`
- **WAIT**: `configurationArguments.waitDuration` + `waitUnit`
- **EMAILV2**: `configurationArguments.emailAssetId` or `configurationArguments.triggeredSend.emailId`
- **EMAIL**: `configurationArguments.emailId`
- **ENGAGEMENTSPLIT**: `criteria`, `waitDuration`, `waitUnit`, `emailActivityKey`
- **ENGAGEMENTDECISION**: `refActivityCustomerKey`, `statsTypeId`
- **UPDATECONTACT**: `dataExtensionKey` or `dataExtensionName`, plus `updateFields` (first item should include `field`/`fieldName`/`name` so it can be promoted to `field`).
- **DATAEXTENSIONUPDATE**: `dataExtensionId`, `field` (auto-copied from `updateFields[0].field|fieldName|fieldId|id|name` when present).

## Entry event definition support
If `entryEventDefinition` (or `eventDefinition` / `eventDefinitionPayload`) is supplied, the tool can create the event definition in SFMC **before** creating the journey draft. The `eventDefinitionKey` (or `key`) is required.

## Examples

### Direct invoke (local testing)
```json
{
  "createInSfmc": false,
  "dryRun": true,
  "journeySpec": {
    "key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "Test Journey",
    "workflowApiVersion": "1.0",
    "triggers": [],
    "activities": []
  }
}
```

### API Gateway (POST /journeydraft)
```json
{
  "httpMethod": "POST",
  "path": "/journeydraft",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"createInSfmc\": false, \"dryRun\": true, \"journeySpec\": {\"key\": \"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\", \"name\": \"Test Journey\", \"workflowApiVersion\": \"1.0\", \"triggers\": [], \"activities\": []}}"
}
```

### Bedrock Action Group
```json
{
  "actionGroup": "sfmc-journey-draft-builder",
  "messageVersion": "1.0",
  "actionGroupInvocationInput": {
    "apiPath": "/journeydraft",
    "verb": "POST",
    "parameters": [
      {"name": "createInSfmc", "value": "false", "type": "boolean"},
      {"name": "dryRun", "value": "true", "type": "boolean"}
    ],
    "requestBody": {
      "content": {
        "application/json": {
          "body": "{\"journeySpec\": {\"key\": \"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\", \"name\": \"Test Journey\", \"workflowApiVersion\": \"1.0\", \"triggers\": [], \"activities\": []}}"
        }
      }
    }
  }
}
```
