# sfmc-journey-draft-builder

## Purpose
This tool validates a Journey Spec payload and can optionally create a draft Journey in the SFMC sandbox. It's designed to be a safe way to build and test journey structures before they are fully implemented.

## Hard guardrails
- **Dodo-only**: This tool is restricted to the "Dodo" brand.
- **Sandbox-only**: All operations are restricted to the SFMC sandbox environment, enforced by the `SFMC_REQUIRED_ENV` environment variable.
- **No production references**: The tool will block requests that point to production hosts.
- **No live sends / activation / publish**: This tool can only create draft journeys. It cannot activate, publish, or send messages.
- **Do not echo SFMC IDs in chat responses**: This is a global agent rule.

## Environment variables
### Required
- `SFMC_SECRET_ARN` or `SFMC_SECRET_ID`: The ARN or ID of the AWS Secrets Manager secret containing SFMC API credentials.
- `SFMC_ENV`: The current SFMC environment (e.g., "sandbox"). Must match `SFMC_REQUIRED_ENV`.
- `SFMC_REQUIRED_ENV`: The required SFMC environment (e.g., "sandbox"). Defaults to "sandbox".

### Optional
- `SFMC_ALLOWED_ACCOUNT_ID`: If set, the tool will only operate on the specified SFMC account ID.
- `SFMC_ALLOWED_HOST_SUFFIXES`: A comma-separated list of allowed host suffixes for SFMC API calls (e.g., ".marketingcloudapps.com").
- `DRY_RUN_DEFAULT`: Defaults to `true`. If `true`, the tool will only validate the journey spec and will not create a draft journey in SFMC unless `dryRun` is explicitly set to `false` in the request.

## Operations

### POST `/journeydraft`
- **`operationId`**: `journeyDraftBuild`
- **Description**: Validates a Journey Spec payload. If `createInSfmc` is `true` and `dryRun` is `false`, it will also attempt to create a draft journey in SFMC.

### POST `/draft`
- **`operationId`**: `journeyDraftBuildAlias`
- **Description**: An alias for `/journeydraft`.

### GET `/healthz`
- **`operationId`**: `healthz`
- **Description**: A lightweight health check that verifies the tool's configuration and guardrails without making any calls to SFMC.

## Examples

### Validate a Journey Spec (dry run)
```json
{
  "apiPath": "/journeydraft",
  "httpMethod": "POST",
  "requestBody": {
    "content": {
      "application/json": {
        "body": "{\\"journeySpec\\": {\\"key\\": \\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\\", \\"name\\": \\"Test Journey\\", \\"workflowApiVersion\\": \\"1.0\\", \\"triggers\\": [], \\"activities\\": []}}"
      }
    }
  }
}
```

### Create a Draft Journey in SFMC
```json
{
  "apiPath": "/journeydraft",
  "httpMethod": "POST",
  "requestBody": {
    "content": {
      "application/json": {
        "body": "{\\"createInSfmc\\": true, \\"dryRun\\": false, \\"journeySpec\\": {\\"key\\": \\"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\\", \\"name\\": \\"Test Journey\\", \\"workflowApiVersion\\": \\"1.0\\", \\"triggers\\": [], \\"activities\\": []}}"
      }
    }
  }
}
```
