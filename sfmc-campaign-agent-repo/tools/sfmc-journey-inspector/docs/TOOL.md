# sfmc-journey-inspector

## Purpose
Read-only SFMC Journey Builder inspection tool (SANDBOX only). Supports searching journeys, fetching a journey (by id or key), listing versions, audit logs, plus compact summaries and topology graphs designed to be Bedrock-safe.

This tool exists to let an agent:
- verify journeys exist and retrieve IDs/keys safely
- understand journey structure (activities/triggers/outcomes)
- extract references to comms assets (best-effort)
- build a lightweight topology graph for reasoning

## Endpoints (OpenAPI)
- POST /searchJourneys (operationId: searchJourneys)
- POST /getJourney (operationId: getJourney)
- POST /listJourneyVersions (operationId: listJourneyVersions)
- POST /getJourneyAuditLog (operationId: getJourneyAuditLog)
- POST /summarizeJourney (operationId: summarizeJourney)
- POST /journeyTopology (operationId: journeyTopology)

## Guardrails
- Sandbox only: SFMC_ENV must equal "sandbox"
- Optional tenant allowlist: SFMC_ALLOWED_ACCOUNT_ID (must match secret account_id/accountId)
- Read-only: no create/update/activate/deactivate calls
- Bedrock safety:
  - response payloads are capped (activitiesSummary, topology nodes/edges, ref scans)
  - optional BEDROCK_FORCE_200=true to prevent Bedrock treating non-2xx as tool failure

## Environment Variables
Required:
- SFMC_SECRET_ID (or SFMC_SECRET_ARN)
- SFMC_ENV=sandbox

Recommended:
- SFMC_ALLOWED_ACCOUNT_ID=xxxxxx
- LOG_LEVEL=INFO
- REST_TIMEOUT=30

Optional debugging:
- DEBUG_REST=false
- DEBUG_REST_TRUNCATE=1200

Journey controls:
- JOURNEY_MAX_PAGE_SIZE=50
- JOURNEY_EXTRAS_ALLOWED=activities,stats,outcome
- JOURNEY_ALLOW_EXTRAS_ALL=false
- JOURNEY_DEFAULT_EXTRAS=
- BEDROCK_FORCE_200=true

Payload caps:
- ACTIVITY_SUMMARY_MAX_ITEMS=150
- TOPOLOGY_MAX_NODES=250
- TOPOLOGY_MAX_EDGES=800
- REF_SCAN_MAX_ITEMS=1200
- REF_SCAN_MAX_DEPTH=8

## Usage notes (agent-facing)
- Prefer idOrKey in the form:
  - "key:<journeyKey>" if you have the key
  - "<GUID>" if you have the journey id
- summarizeJourney and journeyTopology are best-effort and may warn if activities were not returned.
- extras are filtered by allowlist. Passing extras="all" is blocked unless JOURNEY_ALLOW_EXTRAS_ALL=true.

## Testing
Use the sample events under /events for:
- direct Lambda test events (simple body JSON)
- Bedrock flattened events (requestBody.content.application/json.properties[])

## IAM permissions (minimum)
- logs:CreateLogGroup/CreateLogStream/PutLogEvents
- secretsmanager:GetSecretValue on the SFMC secret
- kms:Decrypt if the secret uses a CMK
- outbound HTTPS access to SFMC endpoints
