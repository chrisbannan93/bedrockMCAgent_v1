import os
import json
import time
import logging
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
    """
    Wraps a tool response for Bedrock Agents.
    Supports the flattened event shape you're seeing in logs.
    """
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

def _http_json(method: str, url: str, headers: dict, payload: Optional[dict] = None, timeout: int = 30) -> Tuple[int, dict]:
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
# (same logic style as your working Lambda)
# -----------------------------
def _normalize_api_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = "/" + p.lstrip("/")
    p = p.rstrip("/")
    return p

def _get_api_path(event: dict) -> str:
    # Flattened Bedrock event has apiPath at top-level (your logs)
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
        if isinstance(val, list):
            return val
        s = (val or "").strip()
        try:
            return json.loads(s)
        except Exception:
            return [x.strip() for x in s.split(",") if x.strip()]
    # default string/unknown
    return val

def _parse_bedrock_params(event: dict) -> Dict[str, Any]:
    """
    Handles the event.requestBody shape you saw in logs:
    {
      "content": {
        "application/json": {
          "properties": [
            {"name": "...", "type": "...", "value": "..."},
            ...
          ]
        }
      }
    }
    And also the alternative "body" shapes.
    """
    out: Dict[str, Any] = {}

    # parameters list (sometimes used)
    plist = event.get("parameters") or (event.get("actionGroupInvocationInput", {}) or {}).get("parameters") or []
    if isinstance(plist, list):
        for p in plist:
            name = p.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(p.get("type"), p.get("value"))

    # requestBody can be nested or top-level
    rb = event.get("requestBody") or (event.get("actionGroupInvocationInput", {}) or {}).get("requestBody") or {}
    if not isinstance(rb, dict):
        return out

    content = rb.get("content") or {}
    if not isinstance(content, dict):
        return out

    aj = content.get("application/json") or content.get("application_json") or {}

    # Shape 1: list of typed params (properties[])
    if isinstance(aj, dict) and "properties" in aj and isinstance(aj["properties"], list):
        for it in aj["properties"]:
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
        return out

    # Shape 2: bare list
    if isinstance(aj, list):
        for it in aj:
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
        return out

    # Shape 3: {"body": "..."} where body is JSON string or object
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

    # Shape 4: requestBody itself has "body"
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
    """
    Accept either ARN or Name/ID.
    This matches your existing working setup using SFMC_SECRET_ID.
    """
    secret_ref = (os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or "").strip()
    if not secret_ref:
        raise ValueError("Missing required env var SFMC_SECRET_ARN or SFMC_SECRET_ID")

    resp = secrets.get_secret_value(SecretId=secret_ref)
    secret_str = resp.get("SecretString") or "{}"
    try:
        return json.loads(secret_str)
    except Exception:
        raise ValueError("SecretString is not valid JSON")

def _get_sfmc_bases(secret: dict) -> Tuple[str, str]:
    """
    Be forgiving: support both your older env var names and the newer ones.
    """
    auth_base = _norm_base(
        os.getenv("SFMC_AUTH_BASE_URL", "")
        or os.getenv("auth_url", "")
        or secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
    )
    rest_base = _norm_base(
        os.getenv("SFMC_REST_BASE_URL", "")
        or os.getenv("rest_url", "")
        or secret.get("rest_base_url", "")
        or secret.get("rest_url", "")
    )

    if not auth_base:
        raise ValueError(
            "Missing auth base URL (set SFMC_AUTH_BASE_URL or auth_url "
            "or put auth_base_url/auth_url in the secret)"
        )

    if not rest_base:
        # Fallback convention: replace .auth. with .rest.
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
# Category path logic (read-only)
# -----------------------------
def _get_category(rest_base: str, headers: dict, category_id: int) -> dict:
    url = f"{rest_base}/asset/v1/content/categories/{int(category_id)}"
    status, body = _http_json("GET", url, headers=headers)
    if status < 200 or status >= 300:
        raise RuntimeError(f"Category lookup failed for id={category_id} ({status}): {body}")
    return body or {}

def build_category_path(
    category_id: int,
    limit_root_category_id: Optional[int] = None,
    max_depth: int = 50,
) -> dict:
    """
    Walks up the category tree:
    category_id -> parentId -> parentId -> ... until:
      - parentId == 0 or None, OR
      - we hit limit_root_category_id (if provided), OR
      - max_depth is reached (safety).
    Returns segments from root-to-leaf and a couple of path strings.
    """
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    segments: List[dict] = []
    current_id: Optional[int] = int(category_id)
    depth = 0

    while current_id and depth < max_depth:
        cat = _get_category(rest_base, headers, current_id)
        cid = cat.get("id")
        name = cat.get("name")
        parent_id = cat.get("parentId")

        segments.append({
            "id": cid,
            "name": name,
            "parentId": parent_id,
        })

        depth += 1

        # Stop if we reached the requested root category
        if limit_root_category_id is not None and cid is not None and int(cid) == int(limit_root_category_id):
            break

        # Stop when we hit SFMC's top-level (parentId == 0 or None)
        if parent_id in (None, 0):
            break

        current_id = int(parent_id)

    if depth >= max_depth:
        raise RuntimeError(f"Category chain too deep or cyclic for starting id={category_id}")

    # segments currently leaf -> root; reverse to root -> leaf
    segments_root_to_leaf = list(reversed(segments))

    # Full name path from absolute root
    full_path_names = "/".join((seg.get("name") or "") for seg in segments_root_to_leaf)

    # Path from limit_root_category_id (if provided and found)
    from_root_path_names: Optional[str] = None
    if limit_root_category_id is not None:
        idx = None
        for i, seg in enumerate(segments_root_to_leaf):
            try:
                if int(seg.get("id")) == int(limit_root_category_id):
                    idx = i
                    break
            except Exception:
                continue
        if idx is not None:
            from_root_path_names = "/".join((seg.get("name") or "") for seg in segments_root_to_leaf[idx:])
        else:
            from_root_path_names = full_path_names  # fallback; root not found in chain

    root_seg = segments_root_to_leaf[0] if segments_root_to_leaf else None

    return {
        "segmentsRootToLeaf": segments_root_to_leaf,
        "fullPathNames": full_path_names,
        "fromRootPathNames": from_root_path_names,
        "rootCategoryId": root_seg.get("id") if root_seg else None,
        "rootCategoryName": root_seg.get("name") if root_seg else None,
    }

# -----------------------------
# Tool handler
# -----------------------------
def _handle_get_category_path(params: Dict[str, Any]) -> Tuple[int, dict]:
    """
    Exposed as: POST /getCategoryPath
    Parameters:
      - categoryId (required, integer)
      - limitRootCategoryId (optional, integer)
      - maxDepth (optional, integer, default 50)
    """
    if "categoryId" not in params:
        return 400, {"ok": False, "error": "categoryId is required"}

    category_id = params.get("categoryId")
    limit_root = params.get("limitRootCategoryId")
    max_depth = params.get("maxDepth", 50)

    try:
        output = build_category_path(
            category_id=int(category_id),
            limit_root_category_id=int(limit_root) if limit_root is not None else None,
            max_depth=int(max_depth or 50),
        )
        body = {
            "ok": True,
            "tool": "category_path_inspector",
            "input": {
                "categoryId": int(category_id),
                "limitRootCategoryId": int(limit_root) if limit_root is not None else None,
                "maxDepth": int(max_depth or 50),
            },
            "output": output,
            "warnings": [],
        }
        return 200, body
    except Exception as e:
        logger.exception("getCategoryPath failed")
        return 500, {"ok": False, "error": str(e)}

# -----------------------------
# Lambda entrypoint
# -----------------------------
def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list(event.keys()))
    logger.info("Raw requestBody: %s", event.get("requestBody"))

    # Bedrock Agent action-group invocation
    if _is_bedrock_event(event):
        api_path = _get_api_path(event)
        params = _parse_bedrock_params(event)

        logger.info("Bedrock apiPath=%s httpMethod=%s", api_path, _get_http_method(event))
        logger.info("Parsed Bedrock params: %s", params)

        if api_path.lower() == "/getcategorypath":
            status, body = _handle_get_category_path(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        body = {"ok": False, "error": f"Unknown apiPath: {api_path}"}
        return _bedrock_actiongroup_response(event, body, http_code=400)

    # Non-Bedrock (e.g., direct API Gateway test)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event)
    if path.lower() == "/getcategorypath":
        status, body = _handle_get_category_path(params)
        return _json_response(body, status)

    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
