# sfmc-health-inspector

Read-only sandbox health checks for SFMC auth + endpoint reachability.

## Routes
- GET /healthz  (no SFMC calls; checks env presence + sandbox guardrail)
- POST /healthreport
- GET  /healthreport (query params supported)
- Aliases: /health, /report (same behavior as /healthreport)

## Modes
- quick (default): runtimeConfig + secretsAccess + accountGuardrail + sfmcAuth + REST+SOAP probes
- configOnly: only runtimeConfig; all SFMC calls skipped
- coldstart: like quick but forces a fresh OAuth token fetch (clears warm token cache)

## Inputs
- mode: quick|configonly|coldstart
- includeRestProbes (aliases: includeRestProbe, includeRest)
- includeSoapProbe (alias: includeSoap)
- forceTokenRefresh (aliases: forceAuthRefresh, simulateColdStart)

## Guardrails
- SFMC_ENV must equal SFMC_REQUIRED_ENV (default sandbox)
- Optional: SFMC_ALLOWED_ACCOUNT_ID must match secret account_id
- Optional: SFMC_ALLOWED_HOST_SUFFIXES restricts auth/rest/soap instance hosts

## Probes performed (quick)
- REST:
  - GET /automation/v1/automations?$pageSize=1
  - GET /interaction/v1/interactions?$pageSize=1
- SOAP:
  - DataExtension Retrieve filtered to Name="__sfmc_health_probe__" (safe)

## Required env vars
- SFMC_ENV=sandbox
- SFMC_SECRET_ID (or SFMC_SECRET_ARN)
- REST_TIMEOUT, SOAP_TIMEOUT recommended

## IAM
- secretsmanager:GetSecretValue on the secret
- kms:Decrypt if needed
- CloudWatch logs permissions
