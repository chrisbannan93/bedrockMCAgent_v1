# Knowledge Base mirror (non-runtime)

This folder is a **local mirror** of the Dodo email style Knowledge Base to support
review and alignment of the email composer Lambda and API schema. The runtime system
continues to retrieve content from the Bedrock Knowledge Base via `knowledgeBaseId`.

Use this folder for:
- Reviewing metadata sidecars (`metadataAttributes`), casing, and filter alignment.
- Validating that KB tagging matches `kbFilters` expectations.
- Citing KB content during analysis and code reviews.

Do **not** assume any files here are used at runtime. Update the Bedrock KB ingestion
pipeline separately if you need runtime changes.

## Suggested layout

Place the full KB mirror directly under this folder, for example:

```
resources/kb/
  rules/
  modules/
  examples/
  ... + metadata sidecars
```
