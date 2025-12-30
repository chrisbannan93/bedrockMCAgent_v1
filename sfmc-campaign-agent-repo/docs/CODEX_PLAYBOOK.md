# Codex Playbook (how to work in this repo)

When improving a tool:
1) Read tools/<tool>/docs/TOOL.md first.
2) Keep OpenAPI + Lambda behavior consistent (update both if needed).
3) Add/adjust tests under tools/<tool>/tests/events/.
4) Preserve hard guardrails:
   - Sandbox only
   - Dodo only
   - No live sends / activation / publish
   - Never echo SFMC IDs back in chat outputs
5) Prefer small, safe changes; avoid large refactors unless necessary.
