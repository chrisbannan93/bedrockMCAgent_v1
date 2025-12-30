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

secrets = boto3.client("secretsmanager", region_name="ap-southeast-2")

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
