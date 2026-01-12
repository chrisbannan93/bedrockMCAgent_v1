# Architecture (High-level)

This repo contains multiple Bedrock “action group” tools (Lambdas + OpenAPI schemas) for a sandbox-only SFMC campaign agent.

## Typical flow (email draft + asset)
1. brief-normalizer (optional): normalize messy brief
2. inspectors (optional): inspect existing config (assets, DEs, journeys, automations)
3. email-composer: compose subject/preheader/html (optionally using KB RAG)
4. sfmc-asset-search /resolveFolder: resolve requested or default safe-zone folder -> categoryId
5. email-asset-writer: create draft HTML Email asset in Content Builder using categoryId + emailBlueprint

## Guardrails
- Dodo only
- Sandbox only
- Draft/spec only (no sends, no activation)
- Never guess IDs; use tool outputs
