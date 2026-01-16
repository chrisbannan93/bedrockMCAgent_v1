# Bedrock KB ingestion checklist

This repo includes a **local KB mirror** under `resources/kb` for review only. Runtime
retrieval uses the Bedrock Knowledge Base identified by `knowledgeBaseId`.

## Checklist
- Ensure the KB source paths preserve the `/kb/` prefix in S3 URIs. The email composer
  ignores retrieval results whose `s3Location.uri` does not include `/kb/`.
- Keep sidecar JSON under 10KB and wrapped in `metadataAttributes`.
- Keep metadata values lowercase for stable equality filters.
- Prefer single-string values for strict `equals` filtering. If you use arrays, confirm
  Bedrock retrieval supports list matching before relying on them.
- After updating the KB source content or metadata, re-run your Bedrock KB ingestion job
  so runtime retrieval reflects the changes.

## Local validation
- `python resources/kb/tools/validate_kb_metadata.py`
- `python resources/kb/tools/validate_kb_metadata.py --allow-lists`
