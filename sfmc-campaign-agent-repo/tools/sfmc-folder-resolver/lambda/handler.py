import os
import json
import logging
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")


# -----------------------------
# Helpers
# -----------------------------
def _norm_base(url: str) -> str:
    url = (url or "").strip()
    return url[:-1] if url.endswith("/") else url


def _json_response(body_obj: dict, status_code: int = 200):
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }


def _safe_snip(obj, limit=1500):
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = str(obj)
    return s[:limit]


def _unwrap_event(event):
    """
    Bedrock often wraps the invocation under actionGroupInvocationInput.
    Sometimes traces show other wrappers; this tries common shapes.
    """
    if not isinstance(event, dict):
        return event

    # Most common
    agi = event.get("actionGroupInvocationInput")
    if isinstance(agi, dict):
        return agi

    # Sometimes nested under invocationInput list
    inv = event.get("invocationInput")
    if isinstance(inv, list):
        for item in inv:
            if isinstance(item, dict) and isinstance(item.get("actionGroupInvocationInput"), dict):
                return item["actionGroupInvocationInput"]

    return event


def _bedrock_actiongroup_response(event, body_obj: dict, http_code: int = 200):
    """
    Wrap response for Bedrock Agent action group invocation.
    Must echo actionGroup/apiPath/httpMethod correctly.
    """
    outer = event if isinstance(event, dict) else {}
    e = _unwrap_event(outer) if isinstance(outer, dict) else {}

    action_group = (
        e.get("actionGroup")
        or e.get("actionGroupName")
        or outer.get("actionGroup")
        or outer.get("actionGroupName")
        or ""
    )
    api_path = e.get("apiPath") or outer.get("apiPath") or ""
    http_method = (
        e.get("httpMethod")
        or e.get("verb")
        or outer.get("httpMethod")
        or outer.get("verb")
        or ""
    )
    http_method = http_method.upper() if isinstance(http_method, str) else ""
    message_version = outer.get("messageVersion") or e.get("messageVersion") or "1.0"

    return {
        "messageVersion": message_version,
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


def _is_bedrock_event(event) -> bool:
    e = _unwrap_event(event)
    return (
        isinstance(e, dict)
        and ("apiPath" in e)
        and ("requestBody" in e or "parameters" in e)
        and ("actionGroup" in e or "actionGroupName" in e or "verb" in e or "httpMethod" in e)
    )


def _to_bool(v, default=True):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n"):
            return False
    return default


def _get_ci(d: dict, key: str):
    """Case-insensitive dict get."""
    if not isinstance(d, dict):
        return None
    if key in d:
        return d.get(key)
    k_low = key.lower()
    for k, v in d.items():
        if isinstance(k, str) and k.lower() == k_low:
            return v
    return None


# -----------------------------
# Deep fallback extraction
# -----------------------------
def _looks_like_json(s: str) -> bool:
    if not isinstance(s, str):
        return False
    t = s.strip()
    return (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]"))


def _deep_find_param(obj, target_key: str):
    """
    Recursively search nested dict/list/stringified JSON for:
      - a key == target_key (case-insensitive), OR
      - a {name: target_key, value: ...} object (case-insensitive)
    """
    if obj is None:
        return None

    # JSON in string
    if isinstance(obj, str) and _looks_like_json(obj):
        try:
            parsed = json.loads(obj)
            found = _deep_find_param(parsed, target_key)
            if found not in (None, ""):
                return found
        except Exception:
            pass

    if isinstance(obj, list):
        for item in obj:
            found = _deep_find_param(item, target_key)
            if found not in (None, ""):
                return found
        return None

    if isinstance(obj, dict):
        tk = target_key.lower()

        # direct key match
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() == tk and v not in (None, ""):
                return v

        # name/value match
        n = _get_ci(obj, "name")
        if isinstance(n, str) and n.lower() == tk:
            v = _get_ci(obj, "value")
            if v not in (None, ""):
                return v

        # common wrappers
        b = _get_ci(obj, "body")
        if isinstance(b, (dict, list)):
            found = _deep_find_param(b, target_key)
            if found not in (None, ""):
                return found
        elif isinstance(b, str) and _looks_like_json(b):
            try:
                parsed = json.loads(b)
                found = _deep_find_param(parsed, target_key)
                if found not in (None, ""):
                    return found
            except Exception:
                pass

        # recurse values
        for v in obj.values():
            found = _deep_find_param(v, target_key)
            if found not in (None, ""):
                return found

    return None


def _merge_name_value_list(params: dict, lst):
    """
    Merge a list that might be [{name,value},...] or other variants.
    """
    if not isinstance(lst, list):
        return

    # flatten one-level nested lists: [[{...}]]
    if len(lst) == 1 and isinstance(lst[0], list):
        lst = lst[0]

    # name/value shape (case-insensitive)
    if all(isinstance(x, dict) for x in lst):
        saw_any = False
        for x in lst:
            n = _get_ci(x, "name")
            if isinstance(n, str) and n:
                params[n] = _get_ci(x, "value")
                saw_any = True
        if saw_any:
            return

    # One-item dict list variants
    if len(lst) == 1 and isinstance(lst[0], dict):
        x = lst[0]
        b = _get_ci(x, "body")
        if isinstance(b, str):
            try:
                obj = json.loads(b)
                if isinstance(obj, dict):
                    params.update(obj)
            except Exception:
                pass
        else:
            params.update(x)


def _extract_params(e: dict) -> dict:
    """
    Extract params from:
      - e["parameters"] (list of {name,value})
      - e["requestBody"]["content"]["application/json*"] (list/dict/string)
      - direct keys for local testing
    """
    params = {}
    if not isinstance(e, dict):
        return params

    # direct keys (local testing)
    for k in ("folderPath", "assetFamily", "createIfMissing"):
        if k in e:
            params[k] = e.get(k)

    # "parameters" (case-insensitive)
    plist = _get_ci(e, "parameters")
    if isinstance(plist, list):
        _merge_name_value_list(params, plist)

    # requestBody content (case-insensitive)
    rb = _get_ci(e, "requestBody") or {}
    content = _get_ci(rb, "content") if isinstance(rb, dict) else None

    app_payload = None
    if isinstance(content, dict):
        for k, v in content.items():
            if isinstance(k, str) and k.lower().startswith("application/json"):
                app_payload = v
                break
    else:
        app_payload = content

    if isinstance(app_payload, list):
        _merge_name_value_list(params, app_payload)
    elif isinstance(app_payload, dict):
        b = _get_ci(app_payload, "body")
        if isinstance(b, str):
            try:
                obj = json.loads(b)
                if isinstance(obj, dict):
                    params.update(obj)
                else:
                    params.update(app_payload)
            except Exception:
                params.update(app_payload)
        else:
            params.update(app_payload)
    elif isinstance(app_payload, str):
        try:
            obj = json.loads(app_payload)
            if isinstance(obj, dict):
                params.update(obj)
        except Exception:
            pass

    return params


def _parse_inputs(event: dict):
    e = _unwrap_event(event)
    params = _extract_params(e)

    folder_path = _get_ci(params, "folderPath")
    asset_family = _get_ci(params, "assetFamily")
    cim = _get_ci(params, "createIfMissing")

    # Deep fallback: if structured parsing failed, search everywhere
    if not folder_path:
        folder_path = _deep_find_param(e, "folderPath") or _deep_find_param(event, "folderPath")
    if not asset_family:
        asset_family = _deep_find_param(e, "assetFamily") or _deep_find_param(event, "assetFamily")
    if cim is None:
        cim = _deep_find_param(e, "createIfMissing") or _deep_find_param(event, "createIfMissing")

    if not asset_family:
        asset_family = os.getenv("DEFAULT_ASSET_FAMILY", "content-builder")

    create_if_missing = _to_bool(cim, default=True)

    if os.getenv("DEBUG_EVENT", "false").lower() in ("1", "true", "yes", "y"):
        logger.info("DEBUG_OUTER_KEYS=%s", list(event.keys()) if isinstance(event, dict) else type(event))
        logger.info("DEBUG_INNER_KEYS=%s", list(e.keys()) if isinstance(e, dict) else type(e))
        logger.info("DEBUG_EVENT_SNIP=%s", _safe_snip(event, int(os.getenv("DEBUG_EVENT_MAX_CHARS", "1500"))))
        logger.info("DEBUG_EXTRACTED_PARAMS=%s", _safe_snip(params, 800))
        logger.info("DEBUG_PARSED folderPath=%s createIfMissing=%s assetFamily=%s", folder_path, create_if_missing, asset_family)

    return folder_path, create_if_missing, asset_family


# -----------------------------
# SFMC config loading
# -----------------------------
def _load_sfmc_config():
    secret_id = os.getenv("SFMC_SECRET_ID", "").strip()
    cfg = {}

    if secret_id:
        resp = secrets.get_secret_value(SecretId=secret_id)
        secret_str = resp.get("SecretString") or "{}"
        data = json.loads(secret_str)

        cfg["client_id"] = data.get("client_id") or data.get("SFMC_CLIENT_ID") or ""
        cfg["client_secret"] = data.get("client_secret") or data.get("SFMC_CLIENT_SECRET") or ""
        cfg["auth_base_url"] = data.get("auth_base_url") or data.get("auth_url") or ""
        cfg["rest_base_url"] = data.get("rest_base_url") or ""
        cfg["account_id"] = str(data.get("account_id") or "").strip()
        cfg["source"] = f"secretsmanager:{secret_id}"
    else:
        cfg["client_id"] = os.getenv("SFMC_CLIENT_ID", "").strip()
        cfg["client_secret"] = os.getenv("SFMC_CLIENT_SECRET", "").strip()
        cfg["auth_base_url"] = os.getenv("SFMC_AUTH_URL", "").strip() or os.getenv("auth_url", "").strip()
        cfg["rest_base_url"] = os.getenv("SFMC_REST_BASE_URL", "").strip() or os.getenv("rest_base_url", "").strip()
        cfg["account_id"] = os.getenv("SFMC_ACCOUNT_ID", "").strip()
        cfg["source"] = "env"

    cfg["auth_base_url"] = _norm_base(cfg.get("auth_base_url"))
    cfg["rest_base_url"] = _norm_base(cfg.get("rest_base_url"))

    missing = []
    if not cfg["client_id"]:
        missing.append("client_id")
    if not cfg["client_secret"]:
        missing.append("client_secret")
    if not cfg["auth_base_url"]:
        missing.append("auth_base_url/auth_url")
    if missing:
        raise RuntimeError("MISSING_SFMC_CONFIG: " + ", ".join(missing))

    return cfg


# -----------------------------
# HTTP (OAuth + Asset API)
# -----------------------------
def _http_json(method: str, url: str, headers: dict = None, body_obj=None, timeout=15):
    headers = headers or {}
    data = None
    if body_obj is not None:
        data = json.dumps(body_obj).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    req = Request(url, data=data, headers=headers, method=method.upper())

    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return resp.getcode(), (json.loads(raw) if raw else {})
    except HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            pass
        try:
            parsed = json.loads(raw) if raw else {"message": str(e)}
        except Exception:
            parsed = {"message": str(e), "raw": raw}
        return e.code, parsed
    except URLError as e:
        raise RuntimeError(f"NETWORK_ERROR: {str(e)}")


def _get_token(cfg: dict):
    token_url = cfg["auth_base_url"] + "/v2/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
    }
    if cfg.get("account_id"):
        payload["account_id"] = cfg["account_id"]

    code, out = _http_json("POST", token_url, headers={}, body_obj=payload, timeout=20)
    if code != 200:
        raise RuntimeError(f"OAUTH_FAILED: http={code} body={out}")

    if "access_token" not in out:
        raise RuntimeError(f"OAUTH_BAD_RESPONSE: {out}")

    rest_base = out.get("rest_instance_url") or cfg.get("rest_base_url")
    rest_base = _norm_base(rest_base or "")
    if not rest_base:
        raise RuntimeError("MISSING_SFMC_CONFIG: rest_base_url (and token response had no rest_instance_url)")

    return out["access_token"], rest_base


# -----------------------------
# Folder resolution (Content Builder categories)
# -----------------------------
def _split_path(folder_path: str):
    return [p.strip() for p in (folder_path or "").split("/") if p.strip()]


def _list_children(rest_base: str, token: str, parent_id: int, page_size: int = 200):
    qs = f"$page=1&$pagesize={page_size}&$orderBy=name%20asc&$filter=parentId%20eq%20{parent_id}"
    url = f"{rest_base}/asset/v1/content/categories?{qs}"
    code, out = _http_json("GET", url, headers={"Authorization": f"Bearer {token}"}, body_obj=None)
    if code != 200:
        raise RuntimeError(f"LIST_CATEGORIES_FAILED: http={code} body={out}")
    return out.get("items", []) or []


def _create_category(rest_base: str, token: str, name: str, parent_id: int):
    url = f"{rest_base}/asset/v1/content/categories"
    payload = {"name": name, "parentId": parent_id, "categoryType": "asset"}
    code, out = _http_json("POST", url, headers={"Authorization": f"Bearer {token}"}, body_obj=payload)
    if code not in (200, 201):
        raise RuntimeError(f"CREATE_CATEGORY_FAILED: http={code} body={out}")
    if "id" not in out:
        raise RuntimeError(f"CREATE_CATEGORY_BAD_RESPONSE: {out}")
    return out


def _resolve_folder(rest_base: str, token: str, folder_path: str, create_if_missing: bool, root_parent_id: int):
    parts = _split_path(folder_path)

    ROOT_NAME = os.getenv("CONTENT_ROOT_NAME", "").strip().lower()
    if ROOT_NAME and parts and parts[0].lower() == ROOT_NAME:
        parts = parts[1:]

    if not parts:
        raise ValueError("folderPath must not be empty")

    created_any = False
    current_parent = int(root_parent_id)

    for segment in parts:
        children = _list_children(rest_base, token, current_parent)

        match = None
        for c in children:
            if str(c.get("name", "")).strip().lower() == segment.lower():
                match = c
                break

        if match:
            current_parent = int(match["id"])
            continue

        if not create_if_missing:
            return {
                "ok": False,
                "error": {
                    "code": "FOLDER_NOT_FOUND",
                    "message": f"Missing folder segment '{segment}' under parentId {current_parent}",
                },
            }

        created_obj = _create_category(rest_base, token, segment, current_parent)
        created_any = True
        current_parent = int(created_obj["id"])

    return {
        "ok": True,
        "output": {
            "categoryId": current_parent,
            "created": created_any,
            "normalizedPath": parts,
            "assetFamily": "content-builder",
        },
    }


# -----------------------------
# Lambda handler
# -----------------------------
def lambda_handler(event, context):
    logger.info("PARSER_VERSION=v5_deep_fallback")

    try:
        folder_path, create_if_missing, asset_family = _parse_inputs(event)
        logger.info("PARSED folderPath=%s createIfMissing=%s assetFamily=%s", folder_path, create_if_missing, asset_family)

        if asset_family != "content-builder":
            body = {
                "ok": False,
                "error": {"code": "UNSUPPORTED_ASSET_FAMILY", "message": f"assetFamily '{asset_family}' not supported yet"},
            }
            return _bedrock_actiongroup_response(event, body, 400) if _is_bedrock_event(event) else _json_response(body, 400)

        if not folder_path:
            body = {"ok": False, "error": {"code": "BAD_REQUEST", "message": "folderPath is required"}}
            return _bedrock_actiongroup_response(event, body, 400) if _is_bedrock_event(event) else _json_response(body, 400)

        cfg = _load_sfmc_config()
        token, rest_base = _get_token(cfg)

        root_parent_id = int(os.getenv("CONTENT_ROOT_PARENT_ID", "0"))
        if root_parent_id <= 0:
            raise RuntimeError("MISSING_ROOT_PARENT: Set CONTENT_ROOT_PARENT_ID to your AI root folder categoryId.")

        resolved = _resolve_folder(rest_base, token, folder_path, create_if_missing, root_parent_id)

        if not resolved.get("ok"):
            body = {
                "ok": False,
                "tool": "folder_resolver",
                "input": {"folderPath": folder_path, "createIfMissing": create_if_missing, "assetFamily": asset_family},
                "error": resolved["error"],
            }
            return _bedrock_actiongroup_response(event, body, 404) if _is_bedrock_event(event) else _json_response(body, 404)

        body = {
            "ok": True,
            "tool": "folder_resolver",
            "input": {"folderPath": folder_path, "createIfMissing": create_if_missing, "assetFamily": asset_family},
            "output": resolved["output"],
            "warnings": [],
        }

        return _bedrock_actiongroup_response(event, body, 200) if _is_bedrock_event(event) else _json_response(body, 200)

    except RuntimeError as e:
        msg = str(e)
        code = "INTERNAL_ERROR"
        if msg.startswith("MISSING_SFMC_CONFIG"):
            code = "MISSING_SFMC_CONFIG"
        elif msg.startswith("OAUTH_") or "OAUTH_FAILED" in msg:
            code = "SFMC_AUTH_FAILED"

        body = {"ok": False, "error": {"code": code, "message": msg}}
        return _bedrock_actiongroup_response(event, body, 500) if _is_bedrock_event(event) else _json_response(body, 500)

    except Exception as e:
        body = {"ok": False, "error": {"code": "INTERNAL_ERROR", "message": str(e)}}
        return _bedrock_actiongroup_response(event, body, 500) if _is_bedrock_event(event) else _json_response(body, 500)
