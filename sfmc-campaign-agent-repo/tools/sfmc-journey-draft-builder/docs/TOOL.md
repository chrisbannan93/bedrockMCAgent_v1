# sfmc-journey-draft-builder

## Purpose
This tool validates a Journey Spec payload and can create a draft journey in the SFMC sandbox. It is read-only by default and will only perform a create operation when explicitly instructed.

## Hard guardrails
- Dodo-only
- Sandbox-only
- No production references
- No live sends / activation / publish
- Do not echo SFMC IDs in chat responses

## Environment variables
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`: The ARN or ID of the AWS Secrets Manager secret containing SFMC API credentials.
- `SFMC_ENV`: The SFMC environment (e.g., "sandbox").
- `SFMC_REQUIRED_ENV`: The required SFMC environment for the tool to operate (e.g., "sandbox").
- `SFMC_ALLOWED_ACCOUNT_ID`: (Optional) The SFMC account ID that the tool is allowed to interact with.
- `SFMC_ALLOWED_HOST_SUFFIXES`: (Optional) A comma-separated list of allowed host suffixes for SFMC API calls.
- `DRY_RUN_DEFAULT`: (Optional) Whether to default to a dry run. Defaults to `true`.

## Operations
- `POST /journeydraft`: Validates and returns a Journey Spec payload. Optionally creates a draft journey in SFMC.
- `POST /draft`: An alias for `/journeydraft`.
- `GET /healthz`: Performs a health check and verifies runtime configuration.

## Examples

### Example 1: Validate a Journey Spec (Dry Run)

This example validates a journey spec without creating it in SFMC.

**Request:**
```json
{
  "dryRun": true,
  "journeySpec": {
    "key": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
    "name": "Test Journey",
    "workflowApiVersion": "1.0",
    "triggers": [],
    "activities": []
  }
}
```

**Response:**
```json
{
  "ok": true,
  "tool": "sfmc_journey_draft_builder",
  "journeySpec": {
    "key": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
    "name": "Test Journey",
    "workflowApiVersion": "1.0",
    "triggers": [],
    "activities": []
  },
  "createAttempted": false
}
```

### Example 2: Create a Draft Journey in SFMC

This example creates a draft journey in SFMC.

**Request:**
```json
{
  "createInSfmc": true,
  "dryRun": false,
  "journeySpec": {
    "key": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
    "name": "Test Journey",
    "workflowApiVersion": "1.0",
    "triggers": [],
    "activities": []
  }
}
```

**Response:**
```json
{
  "ok": true,
  "tool": "sfmc_journey_draft_builder",
  "journeySpec": {
    "key": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
    "name": "Test Journey",
    "workflowApiVersion": "1.0",
    "triggers": [],
    "activities": []
  },
  "createAttempted": true,
  "sfmcCreateResult": {

  }
}
```

## Known issues / TODO
- The tool does not yet support updating existing journeys.
- The `sfmcCreateResult` in the response is not yet fully populated with the SFMC API response.
