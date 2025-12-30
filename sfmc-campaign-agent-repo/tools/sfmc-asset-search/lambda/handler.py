import os
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import boto3

# Add the tools directory to the path so that we can import the shared helpers
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from shared.helpers import (
    _bedrock_actiongroup_response,
    _get_access_token,
    _get_api_path,
    _get_http_method,
    _http_json,
    _is_bedrock_event,
    _json_response,
    _parse_bedrock_params,
    _sfmc_headers,
)


logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager", region_name="ap-southeast-2")


# -----------------------------
# Folder Resolution (Content Builder categories)
# -----------------------------
def _normalize_folder_path(folder_path: str) -> List[str]:
    return [p.strip() for p in (folder_path or "").split("/") if p.strip()]


def _get_children_categories(rest_base: str, headers: dict, parent_id: int) -> List[dict]:
    url1 = f"{rest_base}/asset/v1/content/categories/{parent_id}/children"
    status, body = _http_json("GET", url1, headers=headers)
    if 200 <= status < 300:
        if isinstance(body, dict):
            return body.get("items") or []
        if isinstance(body, list):
            return body
        return []

    url2 = f"{rest_base}/asset/v1/content/categories?parentId={parent_id}"
    status2, body2 = _http_json("GET", url2, headers=headers)
    if 200 <= status2 < 300:
        if isinstance(body2, dict):
            return body2.get("items") or []
        if isinstance(body2, list):
            return body2
        return []

    logger.warning(
        "Could not list children categories (parentId=%s). status1=%s status2=%s",
        parent_id,
        status,
        status2,
    )
    return []


def _create_category(rest_base: str, headers: dict, name: str, parent_id: int) -> int:
    url = f"{rest_base}/asset/v1/content/categories"
    payload = {
        "name": name,
        "parentId": parent_id,
        "description": "Auto-created by Lambda folder resolver for pathing.",
    }
    status, body = _http_json("POST", url, headers=headers, payload=payload)
    if status < 200 or status >= 300:
        raise RuntimeError(f"Create category failed ({status}): {body}")

    cid = body.get("id") if isinstance(body, dict) else None
    if not cid:
        raise RuntimeError(f"Create category response missing id: {body}")
    return int(cid)


def resolve_folder(
    folder_path: str,
    create_if_missing: bool = True,
    asset_family: str = "content-builder",
) -> dict:
    parts = _normalize_folder_path(folder_path)
    if not parts:
        raise ValueError("folderPath is required")

    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    current_parent = 0
    created_any = False

    for segment in parts:
        children = _get_children_categories(rest_base, headers, current_parent)
        match = None
        for c in children:
            if (c.get("name") or "").strip().lower() == segment.lower():
                match = c
                break

        if match:
            current_parent = int(match.get("id"))
            continue

        if not create_if_missing:
            raise FileNotFoundError(
                f"Folder segment not found under parentId={current_parent}: {segment}"
            )

        new_id = _create_category(rest_base, headers, segment, current_parent)
        created_any = True
        current_parent = new_id

    return {
        "categoryId": current_parent,
        "created": created_any,
        "normalizedPath": parts,
        "assetFamily": asset_family,
    }


# -----------------------------
# Asset Search
# -----------------------------
def _op_to_sfmc_name_operator(name_operator: Optional[str]) -> Tuple[str, str]:
    op = (name_operator or "").strip().lower()
    if op in ("contains", "like", ""):
        return "like", "contains"
    if op in ("startswith", "starts_with", "starts"):
        return "like", "starts"
    if op in ("endswith", "ends_with", "ends"):
        return "like", "ends"
    if op in ("equals", "eq"):
        return "equals", "raw"
    return "like", "contains"


def _apply_value_mode(text: str, mode: str) -> str:
    if mode == "contains":
        return f"%{text}%"
    if mode == "starts":
        return f"{text}%"
    if mode == "ends":
        return f"%{text}"
    return text


def _or_group(operands: List[dict]) -> dict:
    if not operands:
        return {}
    node = operands[0]
    for nxt in operands[1:]:
        node = {"leftOperand": node, "logicalOperator": "OR", "rightOperand": nxt}
    return node


def _and_group(operands: List[dict]) -> dict:
    if not operands:
        return {}
    node = operands[0]
    for nxt in operands[1:]:
        node = {"leftOperand": node, "logicalOperator": "AND", "rightOperand": nxt}
    return node


def search_assets(
    query_text: Optional[str] = None,
    name_operator: Optional[str] = None,
    folder_path: Optional[str] = None,
    category_id: Optional[int] = None,
    asset_type_ids: Optional[List[int]] = None,
    asset_type_names: Optional[List[str]] = None,
    page: int = 1,
    page_size: int = 25,
    sort_by: str = "modifiedDate",
    sort_dir: str = "DESC",
    fields: Optional[List[str]] = None,
) -> dict:
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    resolved_category_id = None
    if category_id is not None:
        resolved_category_id = int(category_id)
    elif folder_path:
        resolved = resolve_folder(folder_path, create_if_missing=False)
        resolved_category_id = int(resolved["categoryId"])

    # Normalise fields
    if not fields:
        fields = [
            "id",
            "name",
            "assetType",
            "category",
            "status",
            "createdDate",
            "modifiedDate",
            "customerKey",
        ]
    else:
        if isinstance(fields, str):
            # Allow comma-separated strings from non-Bedrock callers
            fields = [f.strip() for f in fields.split(",") if f.strip()]
        elif isinstance(fields, list):
            fields = [str(f) for f in fields]
        else:
            fields = [str(fields)]

    filters: List[dict] = []

    if query_text:
        op, mode = _op_to_sfmc_name_operator(name_operator)
        val = _apply_value_mode(query_text, mode)
        filters.append({"property": "name", "simpleOperator": op, "value": val})

    if resolved_category_id is not None:
        filters.append(
            {"property": "category.id", "simpleOperator": "equals", "value": resolved_category_id}
        )

    if asset_type_ids:
        filters.append(
            _or_group(
                [
                    {
                        "property": "assetType.id",
                        "simpleOperator": "equals",
                        "value": int(x),
                    }
                    for x in asset_type_ids
                ]
            )
        )

    if asset_type_names:
        filters.append(
            _or_group(
                [
                    {
                        "property": "assetType.name",
                        "simpleOperator": "equals",
                        "value": str(x),
                    }
                    for x in asset_type_names
                ]
            )
        )

    query_node = _and_group(filters) if filters else {}

    payload = {
        "page": int(page or 1),
        "pageSize": int(page_size or 25),
        "sort": [
            {
                "property": sort_by or "modifiedDate",
                "direction": (sort_dir or "DESC").upper(),
            }
        ],
    }
    if query_node:
        payload["query"] = query_node

    url = f"{rest_base}/asset/v1/content/assets/query"
    status, body = _http_json("POST", url, headers=headers, payload=payload)

    if status < 200 or status >= 300:
        raise RuntimeError(f"Asset search failed ({status}): {body}")

    items = body.get("items") or []
    count = body.get("count")
    if count is None:
        count = body.get("totalResults", len(items))

    # Helper for nested fields like "category.id"
    def _get_nested_field(obj: dict, field: str):
        if "." not in field:
            return obj.get(field)
        cur = obj
        for part in field.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
            if cur is None:
                return None
        return cur

    projected = []
    for it in items:
        out = {}
        for f in fields:
            out[f] = _get_nested_field(it, f)
        projected.append(out)

    return {
        "count": int(count or 0),
        "page": int(body.get("page") or page or 1),
        "pageSize": int(body.get("pageSize") or page_size or 25),
        "items": projected,
    }


# -----------------------------
# Tool handlers
# -----------------------------
def _handle_resolve_folder(params: Dict[str, Any]) -> Tuple[int, dict]:
    folder_path = params.get("folderPath")
    if not folder_path:
        return 400, {"ok": False, "error": "folderPath is required"}

    create_if_missing = params.get("createIfMissing", True)
    asset_family = params.get("assetFamily", "content-builder")

    try:
        output = resolve_folder(
            folder_path,
            create_if_missing=bool(create_if_missing),
            asset_family=str(asset_family),
        )
        return 200, {
            "ok": True,
            "tool": "folder_resolver",
            "input": {
                "folderPath": folder_path,
                "createIfMissing": bool(create_if_missing),
                "assetFamily": str(asset_family),
            },
            "output": output,
            "warnings": [],
        }
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("resolveFolder failed")
        return 500, {"ok": False, "error": str(e)}


def _handle_search_assets(params: Dict[str, Any]) -> Tuple[int, dict]:
    query_text = params.get("queryText")
    name_operator = params.get("nameOperator")
    folder_path = params.get("folderPath")
    category_id = params.get("categoryId")
    asset_type_ids = params.get("assetTypeIds")
    asset_type_names = params.get("assetTypeNames")
    page = params.get("page", 1)
    page_size = params.get("pageSize", 25)
    sort_by = params.get("sortBy", "modifiedDate")
    sort_dir = params.get("sortDir", "DESC")
    fields = params.get("fields")

    # Default fields if not supplied
    if not fields:
        fields = [
            "id",
            "name",
            "assetType",
            "category",
            "status",
            "createdDate",
            "modifiedDate",
            "customerKey",
        ]

    if isinstance(asset_type_ids, list):
        asset_type_ids = [int(x) for x in asset_type_ids]
    else:
        asset_type_ids = None

    if isinstance(asset_type_names, list):
        asset_type_names = [str(x) for x in asset_type_names]
    else:
        asset_type_names = None

    try:
        output = search_assets(
            query_text=query_text,
            name_operator=name_operator,
            folder_path=folder_path,
            category_id=int(category_id) if category_id is not None else None,
            asset_type_ids=asset_type_ids,
            asset_type_names=asset_type_names,
            page=int(page or 1),
            page_size=int(page_size or 25),
            sort_by=str(sort_by or "modifiedDate"),
            sort_dir=str(sort_dir or "DESC"),
            fields=fields,
        )
        return 200, {
            "ok": True,
            "tool": "asset_search",
            "input": {
                "queryText": query_text,
                "nameOperator": name_operator,
                "folderPath": folder_path,
                "categoryId": category_id,
                "assetTypeIds": asset_type_ids,
                "assetTypeNames": asset_type_names,
                "page": int(page or 1),
                "pageSize": int(page_size or 25),
                "fields": fields,
                "sortBy": sort_by,
                "sortDir": sort_dir,
            },
            "output": output,
            "warnings": [],
        }
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("searchAssets failed")
        return 500, {"ok": False, "error": str(e)}


# -----------------------------
# Lambda entrypoint
# -----------------------------
def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list(event.keys()))
    logger.info("Raw requestBody: %s", event.get("requestBody"))

    if _is_bedrock_event(event):
        api_path = _get_api_path(event)
        params = _parse_bedrock_params(event)

        logger.info(
            "Bedrock apiPath=%s httpMethod=%s",
            api_path,
            _get_http_method(event),
        )
        logger.info("Parsed Bedrock params: %s", params)

        if api_path.lower() == "/resolvefolder":
            status, body = _handle_resolve_folder(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path.lower() == "/searchassets":
            status, body = _handle_search_assets(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        body = {"ok": False, "error": f"Unknown apiPath: {api_path}"}
        return _bedrock_actiongroup_response(event, body, http_code=400)

    # Non-bedrock (e.g. direct API / API Gateway)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event)
    if path.lower() == "/resolvefolder":
        status, body = _handle_resolve_folder(params)
        return _json_response(body, status)

    if path.lower() == "/searchassets":
        status, body = _handle_search_assets(params)
        return _json_response(body, status)

    return _json_response(
        {"ok": False, "error": f"Unknown path: {path}"},
        400,
    )
