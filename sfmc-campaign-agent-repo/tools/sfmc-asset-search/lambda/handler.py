import os
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
}

# -----------------------------
# Helpers: HTTP / Responses
# -----------------------------
def _norm_base(url: str) -> str:
    url = (url or "").strip()
    return url[:-1] if url.endswith("/") else url


def _json_response(body_obj: dict, status_code: int = 200) -> dict:
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }


def _bedrock_actiongroup_response(event: dict, body_obj: dict, http_code: int = 200) -> dict:
    # Works for BOTH event shapes (nested + flattened)
    action_group = (
        event.get("actionGroup")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("actionGroupName", "")
        or ""
    )
    api_path = _get_api_path(event)
    http_method = _get_http_method(event)

    return {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": http_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(body_obj)
                }
            },
        },
    }


def _is_bedrock_event(event: dict) -> bool:
    # Bedrock action group events always include messageVersion in practice
    return "messageVersion" in event and "response" not in event


def _http_json(
    method: str,
    url: str,
    headers: dict,
    payload: Optional[dict] = None,
    timeout: int = 30,
) -> Tuple[int, dict]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers = dict(headers or {})
        headers["Content-Type"] = "application/json"

    req = Request(url=url, data=data, headers=headers, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return resp.status, {}
            return resp.status, json.loads(raw)
    except HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        try:
            return e.code, json.loads(raw) if raw else {"error": raw}
        except Exception:
            return e.code, {"error": raw or str(e)}
    except URLError as e:
        return 599, {"error": f"URLError: {e}"}


# -----------------------------
# Bedrock event extraction
# -----------------------------
def _normalize_api_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = "/" + p.lstrip("/")
    p = p.rstrip("/")
    return p


def _get_api_path(event: dict) -> str:
    # Flattened Bedrock event has apiPath at top-level
    p = event.get("apiPath")
    if p:
        return _normalize_api_path(p)

    # Some variants nest it
    agi = event.get("actionGroupInvocationInput", {}) or {}
    p2 = agi.get("apiPath")
    if p2:
        return _normalize_api_path(p2)

    # API Gateway / others
    return _normalize_api_path(event.get("rawPath") or event.get("path") or "")


def _get_http_method(event: dict) -> str:
    # Flattened Bedrock event has httpMethod at top-level
    m = event.get("httpMethod")
    if m:
        return str(m).upper()

    agi = event.get("actionGroupInvocationInput", {}) or {}
    v = agi.get("verb")
    if v:
        return str(v).upper()

    return "POST"


def _coerce_typed_value(typ: str, val: Any) -> Any:
    """
    Coerce Bedrock-typed values (integer, boolean, array, etc.).
    This now understands the weird <item>id</item><item>name</item> encoding
    that Tools uses for array-of-string parameters.
    """
    typ = (typ or "").lower()

    if typ == "integer":
        try:
            return int(val)
        except Exception:
            return None

    if typ == "boolean":
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "y")

    if typ == "array":
        # Already a list? Use it as-is.
        if isinstance(val, list):
            return val
        if val is None:
            return []

        s = str(val).strip()

        # 1) Try JSON: e.g. '["id","name"]'
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

        # 2) Bedrock "array of strings" encoding:
        #    "<item>id</item><item>name</item>..."
        if "<item>" in s and "</item>" in s:
            items = re.findall(r"<item>(.*?)</item>", s)
            return [i.strip() for i in items if i.strip()]

        # 3) Fallback: comma-separated string
        return [x.strip() for x in s.split(",") if x.strip()]

    # default: string / unknown
    return val


def _parse_bedrock_params(event: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    # parameters list (sometimes used)
    plist = (
        event.get("parameters")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("parameters")
        or []
    )
    if isinstance(plist, list):
        for p in plist:
            name = p.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(p.get("type"), p.get("value"))

    # requestBody can be nested or top-level
    rb = (
        event.get("requestBody")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("requestBody")
        or {}
    )
    if not isinstance(rb, dict):
        return out

    content = rb.get("content") or {}
    if not isinstance(content, dict):
        return out

    aj = content.get("application/json") or content.get("application_json") or {}

    # Shape 0: {"properties": [ {name,type,value}, ... ]}
    if isinstance(aj, dict):
        props = aj.get("properties")
        if isinstance(props, list):
            for it in props:
                name = it.get("name")
                if not name:
                    continue
                out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            return out

    # Shape 1: list of typed params
    if isinstance(aj, list):
        for it in aj:
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
        return out

    # Shape 2: {"body": "..."} where body is JSON string or object
    if isinstance(aj, dict):
        body = aj.get("body")
        if body is not None:
            if isinstance(body, dict):
                out.update(body)
                return out
            if isinstance(body, str):
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        out.update(parsed)
                except Exception:
                    pass
                return out

    # Shape 3: requestBody itself has "body"
    if "body" in rb:
        b = rb.get("body")
        if isinstance(b, dict):
            out.update(b)
        elif isinstance(b, str):
            try:
                parsed = json.loads(b)
                if isinstance(parsed, dict):
                    out.update(parsed)
            except Exception:
                pass

    return out


# -----------------------------
# Helpers: Secrets + SFMC Auth
# -----------------------------
def _load_secret_json() -> dict:
    # accept either ARN or Name/ID
    secret_ref = (
        os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or ""
    ).strip()
    if not secret_ref:
        raise ValueError("Missing required env var SFMC_SECRET_ARN or SFMC_SECRET_ID")

    resp = secrets.get_secret_value(SecretId=secret_ref)
    secret_str = resp.get("SecretString") or "{}"
    try:
        return json.loads(secret_str)
    except Exception:
        raise ValueError("SecretString is not valid JSON")


def _get_sfmc_bases(secret: dict) -> Tuple[str, str]:
    # Prefer explicit envs; fall back to your existing auth_url; then the secret
    auth_base = _norm_base(
        os.getenv("SFMC_AUTH_BASE_URL", "")
        or os.getenv("auth_url", "")
        or secret.get("auth_base_url", "")
    )
    rest_base = _norm_base(
        os.getenv("SFMC_REST_BASE_URL", "")
        or os.getenv("rest_url", "")
        or secret.get("rest_base_url", "")
    )

    if not auth_base:
        raise ValueError(
            "Missing auth base URL (set SFMC_AUTH_BASE_URL, auth_url, or secret.auth_base_url)"
        )
    if not rest_base:
        # derive REST from AUTH if needed
        rest_base = auth_base.replace(".auth.", ".rest.")
    return auth_base, rest_base


def _get_access_token() -> Tuple[str, str]:
    now = int(time.time())
    if _TOKEN_CACHE["access_token"] and now < int(_TOKEN_CACHE["expires_at"] or 0) - 30:
        return _TOKEN_CACHE["access_token"], _TOKEN_CACHE["rest_base_url"]

    secret = _load_secret_json()
    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id and client_secret")

    auth_base, rest_base = _get_sfmc_bases(secret)
    token_url = f"{auth_base}/v2/token"

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    status, body = _http_json("POST", token_url, headers={}, payload=payload)
    if status < 200 or status >= 300:
        raise RuntimeError(f"SFMC auth failed ({status}): {body}")

    access_token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 1200)

    if not access_token:
        raise RuntimeError(f"SFMC auth missing access_token: {body}")

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base

    return access_token, rest_base


def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


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
