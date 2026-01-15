# KB repository import guidance

This repo expects the Dodo email style knowledge base (KB) to live outside the codebase and be
retrieved at runtime via Bedrock (`EMAIL_STYLE_KB_ID`). In this environment, outbound access to
GitHub is blocked (403), so the KB cannot be cloned directly.

## Recommended way to provide the KB for review

Provide the KB contents by uploading a zip/tarball (or a curated subset of the KB files) into the
workspace. After upload, extract it under a local directory such as:

```
/workspace/bedrockMCAgent_v1/dodo-bedrock-kb
```

## Alternative: Add as a submodule (requires GitHub access)

If GitHub access is available in your environment, you can add the KB as a submodule:

```
git submodule add https://github.com/chrisbannan93/dodo-bedrock-kb external/dodo-bedrock-kb
```

This is **not possible** in the current sandbox because the network blocks outbound GitHub access.
