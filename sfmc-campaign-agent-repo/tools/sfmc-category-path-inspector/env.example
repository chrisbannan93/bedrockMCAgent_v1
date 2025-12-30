# sfmc-category-path-inspector

## Purpose
Given a Salesforce Marketing Cloud (SFMC) Content Builder `categoryId`, this tool walks up the folder tree (via `parentId`) and returns the full folder path and ordered segments (root → leaf).

Use this to:
- verify a `categoryId` belongs under the AI “safe zone” root
- debug where an asset actually lives
- convert IDs returned by `sfmc-asset-search` into readable folder paths

This tool is **read-only** (no folder creation).

---

## Endpoint
POST `/getCategoryPath`

---

## Inputs
### Required
- `categoryId` (integer, >= 1)
  - Source: typically `items[].category.id` from `sfmc-asset-search`

### Optional
- `limitRootCategoryId` (integer, >= 1)
  - If provided, `fromRootPathNames` is computed starting at this category.
  - Useful for producing a path relative to your AI safe-zone root folder.
- `maxDepth` (integer, default 50, max 200)
  - Safety cap to avoid infinite loops or bad data.

---

## Output (success)
Returns:

- `segmentsRootToLeaf`: array of `{ id, name, parentId }` from root → leaf
- `fullPathNames`: `"Root/Child/Leaf"` using segment names
- `fromRootPathNames`: same as above but starting at `limitRootCategoryId` (nullable)
- `rootCategoryId`, `rootCategoryName`: first segment in the chain (nullable)

Wrapper shape:

```json
{
  "ok": true,
  "tool": "category_path_inspector",
  "input": { "categoryId": 123, "limitRootCategoryId": 456, "maxDepth": 50 },
  "output": { ... },
  "warnings": []
}
