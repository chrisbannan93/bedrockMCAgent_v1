# Architecture (High-level)

This repo contains multiple Bedrock “action group” tools (Lambdas + OpenAPI schemas) for a sandbox-only SFMC campaign agent.

## Typical flow (email draft + asset)
1. brief-normalizer (optional): normalize messy brief
2. inspectors (optional): inspect existing config (assets, DEs, journeys, automations)
3. folder-resolver: resolve/create safe-zone folder -> categoryId
4. email-composer: compose subject/preheader/html (optionally using KB RAG)
5. email-asset-writer: create draft HTML Email asset in Content Builder using categoryId + emailBlueprint

## Guardrails
- Dodo only
- Sandbox only
- Draft/spec only (no sends, no activation)
- Never guess IDs; use tool outputs
