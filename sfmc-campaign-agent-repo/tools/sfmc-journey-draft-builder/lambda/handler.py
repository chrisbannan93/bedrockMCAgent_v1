import os
import json
import time
import base64
import logging
import re
from typing import Any, Dict, Optional, Tuple, List
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

import boto3

# -----------------------------
# Tool metadata
# -----------------------------
TOOL_NAME = "sfmc_journey_draft_builder"
TOOL_VERSION = "2025-12-30"
OUTPUT_SCHEMA_VERSION = "0.1.0"

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Config / Guardrails
# -----------------------------
REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "20"))

SFMC_ENV = (os.getenv("SFMC_ENV") or "").strip().lower()
REQUIRED_SFMC_ENV = (os.getenv("SFMC_REQUIRED_ENV") or "sandbox").strip().lower()

SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

SFMC_ALLOWED_HOST_SUFFIXES = [
    s.strip().lower()
    for s in (os.getenv("SFMC_ALLOWED_HOST_SUFFIXES") or "").split(",")
    if s.strip()
]

SFMC_SECRET_REF = (os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or "").strip()

DRY_RUN_DEFAULT = (os.getenv("DRY_RUN_DEFAULT") or "true").strip().lower() in ("true", "1", "yes", "y", "on")

MAX_TRIGGERS = int(os.getenv("MAX_TRIGGERS", "10"))
MAX_ACTIVITIES = int(os.getenv("MAX_ACTIVITIES", "200"))
MAX_SPEC_BYTES = int(os.getenv("MAX_SPEC_BYTES", "300000"))  # safety cap

SUPPORTED_ROUTES = {
    "GET": {"/healthz"},
    "POST": {"/journeydraft", "/journey-draft", "/draft"},
}

_BOOL_TRUE = {"true", "1", "yes", "y", "on"}
_BOOL_FALSE = {"false", "0", "no", "n", "off"}

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

# -----------------------------
# Warm token cache
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
    "auth_base_url": None,
    "account_id": None,
}


def _reset_token_cache() -> None:
    _TOKEN_CACHE["access_token"] = None
    _TOKEN_CACHE["expires_at"] = 0
    _TOKEN_CACHE["rest_base_url"] = None
    _TOKEN_CACHE["auth_base_url"] = None
    _TOKEN_CACHE["account_id"] = None


# -----------------------------
# Helpers
# -----------------------------
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _perf_ms() -> float:
    return time.perf_counter() * 1000.0


def _json_response(body_obj: dict, status_code: int = 200) -> dict:
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }


def _is_bedrock_event(event: dict) -> bool:
    return "messageVersion" in event and "response" not in event


def _normalize_api_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = "/" + p.lstrip("/")
    return p.rstrip("/") or "/"


def _get_api_path(event: dict) -> str:
    p = event.get("apiPath")
    if p:
        return _normalize_api_path(p)

    agi = event.get("actionGroupInvocationInput", {}) or {}
    p2 = agi.get("apiPath")
    if p2:
        return _normalize_api_path(p2)

    return _normalize_api_path(
        event.get("rawPath")
        or event.get("path")
        or (event.get("requestContext", {}) or {}).get("http", {}).get("path")
        or ""
    )


def _get_http_method(event: dict) -> str:
    m = event.get("httpMethod")
    if m:
        return str(m).upper()

    agi = event.get("actionGroupInvocationInput", {}) or {}
    v = agi.get("verb")
    if v:
        return str(v).upper()

    rc = event.get("requestContext", {}) or {}
    http = (rc.get("http", {}) or {})
    if http.get("method"):
        return str(http.get("method")).upper()

    return "POST"


def _bedrock_actiongroup_response(event: dict, body_obj: dict, http_code: int = 200) -> dict:
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


def _is_supported_route(method_upper: str, path_lower: str) -> bool:
    m = (method_upper or "").strip().upper()
    p = (path_lower or "").strip().lower()
    return bool(m and p and (m in SUPPORTED_ROUTES) and (p in SUPPORTED_ROUTES[m]))


def _allowed_methods_for_path(path_lower: str) -> List[str]:
    p = (path_lower or "").strip().lower()
    allowed = []
    for m, paths in SUPPORTED_ROUTES.items():
        if p in paths:
            allowed.append(m)
    return sorted(allowed)


def _to_bool_strict(v: Any, default: bool) -> Tuple[bool, bool]:
    if v is None:
        return default, True
    if isinstance(v, bool):
        return v, True
    s = str(v).strip().lower()
    if s in _BOOL_TRUE:
        return True, True
    if s in _BOOL_FALSE:
        return False, True
    return default, False


def _maybe_json_loads(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return None


def _maybe_decode_body(event: dict) -> Optional[str]:
    b = event.get("body")
    if b is None:
        return None
    if isinstance(b, dict):
        return None
    if not isinstance(b, str):
        return None
    if not b.strip():
        return ""
    if event.get("isBase64Encoded") is True:
        try:
            return base64.b64decode(b).decode("utf-8")
        except Exception:
            return b
    return b


def _unwrap_bedrock_scalar(v: Any) -> Any:
    if isinstance(v, dict) and v:
        for k in ("stringValue", "booleanValue", "intValue", "integerValue", "doubleValue", "floatValue", "value"):
            if k in v:
                return v.get(k)
    return v


def _coerce_bedrock_value(v: Any, declared_type: Optional[str]) -> Any:
    v = _unwrap_bedrock_scalar(v)
    t = (declared_type or "").strip().lower()
    if t == "boolean":
        b, _ok = _to_bool_strict(v, default=False)
        return b
    if t in ("integer", "int"):
        try:
            return int(str(v).strip())
        except Exception:
            return v
    if t in ("number", "float", "double"):
        try:
            return float(str(v).strip())
        except Exception:
            return v
    return v


def _parse_actiongroup_kv_list(kv_list: Any) -> dict:
    out: Dict[str, Any] = {}
    if not isinstance(kv_list, list):
        return out
    for item in kv_list:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").strip()
        if not name:
            continue
        out[name] = _coerce_bedrock_value(item.get("value"), item.get("type"))
    return out


def _parse_json_body(event: dict) -> dict:
    """
    Supports:
      - Direct invoke: event itself is params dict
      - API GW: event["body"] dict or JSON string (supports base64)
      - Bedrock: actionGroupInvocationInput.parameters and requestBody.content.application/json
    """
    # Direct invoke convenience
    direct_block_keys = {
        "body", "requestContext", "actionGroupInvocationInput", "httpMethod", "rawPath", "path", "apiPath",
        "headers", "queryStringParameters", "routeKey", "version", "requestBody", "messageVersion"
    }
    if isinstance(event, dict) and not any(k in event for k in direct_block_keys):
        return dict(event)

    # Standard API GW
    if isinstance(event.get("body"), dict):
        return event["body"]

    b_str = _maybe_decode_body(event)
    if isinstance(b_str, str) and b_str.strip():
        parsed = _maybe_json_loads(b_str)
        if isinstance(parsed, dict):
            return parsed

    # Bedrock
    agi = (event.get("actionGroupInvocationInput", {}) or {})
    params_from_agi = _parse_actiongroup_kv_list(agi.get("parameters") or event.get("parameters"))

    rb = event.get("requestBody") or agi.get("requestBody") or {}
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        aj = content.get("application/json") or content.get("application_json")

        if isinstance(aj, str) and aj.strip():
            aj_parsed = _maybe_json_loads(aj)
            if isinstance(aj_parsed, (dict, list)):
                aj = aj_parsed

        if isinstance(aj, dict):
            body = aj.get("body")
            if isinstance(body, str) and body.strip():
                parsed_body = _maybe_json_loads(body)
                if isinstance(parsed_body, dict):
                    merged = dict(params_from_agi)
                    merged.update(parsed_body)
                    return merged
            if isinstance(body, dict):
                merged = dict(params_from_agi)
                merged.update(body)
                return merged
            # Merge wrapper keys (excluding body)
            merged = dict(params_from_agi)
            for k, v in aj.items():
                if k == "body":
                    continue
                merged[k] = v
            return merged

        if isinstance(aj, list):
            merged = dict(params_from_agi)
            merged.update(_parse_actiongroup_kv_list(aj))
            return merged

    return dict(params_from_agi)


def _sanitize_requested_inputs(d: dict) -> dict:
    if not isinstance(d, dict):
        return {}
    redacted = {}
    for k, v in d.items():
        ks = str(k).lower()
        if any(x in ks for x in ("secret", "password", "token", "client_secret", "authorization", "bearer")):
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted


# -----------------------------
# HTTP + SFMC Auth
# -----------------------------
def _ensure_scheme(url: str, default_scheme: str = "https") -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return f"{default_scheme}://{u}"


def _url_base_only(url: str) -> str:
    u = _ensure_scheme(url)
    p = urlparse(u)
    scheme = p.scheme or "https"
    netloc = p.netloc
    if not netloc and p.path:
        netloc = p.path.split("/", 1)[0]
    return f"{scheme}://{netloc}" if netloc else ""


def _strip_known_auth_paths(auth_url_or_base: str) -> str:
    base = _url_base_only(auth_url_or_base)
    return base[:-1] if base.endswith("/") else base


def _swap_host_segment(url_base: str, old: str, new: str) -> str:
    u = _ensure_scheme(url_base)
    p = urlparse(u)
    scheme = p.scheme or "https"
    netloc = p.netloc or ""
    if not netloc and p.path:
        netloc = p.path.split("/", 1)[0]
    if not netloc:
        return ""
    return f"{scheme}://{netloc.replace(old, new)}"


def _host_from_url(url: str) -> Optional[str]:
    try:
        u = (url or "").strip()
        if not u:
            return None
        u = _ensure_scheme(u)
        p = urlparse(u)
        netloc = p.netloc or ""
        if not netloc and p.path:
            netloc = p.path.split("/", 1)[0]
        host = netloc.split("@")[-1]
        host = host.split(":", 1)[0]
        return host or None
    except Exception:
        return None


def _host_allowed(host: Optional[str]) -> bool:
    if not SFMC_ALLOWED_HOST_SUFFIXES:
        return True
    if not host:
        return False
    h = host.lower()
    return any(h.endswith(suf) for suf in SFMC_ALLOWED_HOST_SUFFIXES)


def _http_json(method: str, url: str, headers: dict, payload: Optional[dict], timeout: int) -> Tuple[int, dict]:
    data = None
    h = dict(headers or {})
    if payload is not None:
        raw = json.dumps(payload).encode("utf-8")
        data = raw
        h["Content-Type"] = "application/json"
        h["Accept"] = "application/json"
    req = Request(url=url, data=data, headers=h, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return resp.status, {}
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}
    except HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8") if e.fp else ""
        except Exception:
            raw = ""
        try:
            return e.code, json.loads(raw) if raw else {"error": raw}
        except Exception:
            return e.code, {"error": raw or str(e)}
    except URLError as e:
        return 599, {"error": f"URLError: {e}"}


def _load_secret_json() -> dict:
    if not SFMC_SECRET_REF:
        raise ValueError("Missing required env var SFMC_SECRET_ARN or SFMC_SECRET_ID")
    resp = secrets.get_secret_value(SecretId=SFMC_SECRET_REF)
    secret_str = resp.get("SecretString") or "{}"
    try:
        return json.loads(secret_str)
    except Exception:
        raise ValueError("SecretString is not valid JSON")


def _secret_account_id(secret: dict) -> Optional[str]:
    acct = secret.get("account_id") or secret.get("accountId")
    acct = str(acct).strip() if acct is not None else ""
    return acct or None


def _enforce_account_guardrail(secret: dict) -> None:
    if not SFMC_ALLOWED_ACCOUNT_ID:
        return
    acct = _secret_account_id(secret)
    if not acct:
        raise ValueError("Guardrail: SFMC_ALLOWED_ACCOUNT_ID set but secret has no account_id/accountId")
    if acct != SFMC_ALLOWED_ACCOUNT_ID:
        raise ValueError(f"Guardrail: account_id {acct} not allowed (expected {SFMC_ALLOWED_ACCOUNT_ID})")


def _get_sfmc_bases(secret: dict) -> Tuple[str, str]:
    auth_candidate = (
        secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
        or secret.get("authUrl", "")
        or ""
    )
    auth_base = _strip_known_auth_paths(auth_candidate)
    if not auth_base:
        raise ValueError("Secret missing auth base URL (auth_url/auth_base_url/authUrl)")

    rest_candidate = secret.get("rest_base_url", "") or secret.get("rest_url", "") or ""
    rest_base = _url_base_only(rest_candidate) if rest_candidate else ""
    if not rest_base:
        rest_base = _swap_host_segment(auth_base, ".auth.", ".rest.") or auth_base.replace(".auth.", ".rest.")

    return auth_base, rest_base


def _get_access_token(force_refresh: bool = False) -> Tuple[str, str, str, dict]:
    now = int(time.time())
    if force_refresh:
        _reset_token_cache()

    if _TOKEN_CACHE["access_token"] and now < int(_TOKEN_CACHE["expires_at"] or 0) - 30:
        remaining = max(0, int(_TOKEN_CACHE["expires_at"] or 0) - now)
        meta = {
            "tokenCacheHit": True,
            "tokenExpiresInSecRemaining": remaining,
            "accountId": _TOKEN_CACHE.get("account_id"),
            "forcedRefreshRequested": bool(force_refresh),
            "forcedRefreshPerformed": False,
        }
        return _TOKEN_CACHE["access_token"], _TOKEN_CACHE["rest_base_url"], _TOKEN_CACHE["auth_base_url"], meta

    secret = _load_secret_json()
    _enforce_account_guardrail(secret)

    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    account_id = secret.get("account_id") or secret.get("accountId")

    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id and client_secret")

    auth_base, rest_base = _get_sfmc_bases(secret)

    # Host suffix guardrail (auth+rest)
    if SFMC_ALLOWED_HOST_SUFFIXES:
        ah = _host_from_url(auth_base)
        rh = _host_from_url(rest_base)
        if not (_host_allowed(ah) and _host_allowed(rh)):
            raise ValueError(f"HostSuffixGuardrailFailed: authHost={ah}, restHost={rh}, allowlist={SFMC_ALLOWED_HOST_SUFFIXES}")

    token_url = f"{auth_base}/v2/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if account_id:
        payload["account_id"] = account_id

    status, body = _http_json("POST", token_url, headers={}, payload=payload, timeout=REST_TIMEOUT)
    if status < 200 or status >= 300:
        raise RuntimeError(f"SFMC auth failed ({status}): {body}")

    access_token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 1200)
    if not access_token:
        raise RuntimeError(f"SFMC auth missing access_token: {body}")

    token_rest = body.get("rest_instance_url") or body.get("restInstanceUrl")
    if token_rest:
        rest_base = _url_base_only(token_rest) or rest_base

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base
    _TOKEN_CACHE["auth_base_url"] = auth_base
    _TOKEN_CACHE["account_id"] = str(account_id).strip() if account_id else _secret_account_id(secret)

    remaining = max(0, (_TOKEN_CACHE["expires_at"] - now))
    meta = {
        "tokenCacheHit": False,
        "tokenExpiresInSecRemaining": remaining,
        "accountId": _TOKEN_CACHE.get("account_id"),
        "forcedRefreshRequested": bool(force_refresh),
        "forcedRefreshPerformed": bool(force_refresh),
    }
    return access_token, rest_base, auth_base, meta


def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


# -----------------------------
# Validation + spec extraction
# -----------------------------
def _validate_uuid(s: Any) -> bool:
    if not s:
        return False
    return bool(_UUID_RE.match(str(s).strip()))


def _prune_server_fields(spec: dict) -> Tuple[dict, List[str]]:
    """
    Remove obvious server-managed fields that often cause create/update rejection.
    """
    warnings = []
    if not isinstance(spec, dict):
        return {}, ["Spec is not an object"]
    pruned = dict(spec)

    for k in ["id", "status", "createdDate", "modifiedDate", "lastPublishedDate", "publishedDate", "versionId"]:
        if k in pruned:
            pruned.pop(k, None)
            warnings.append(f"Removed server-managed field '{k}' from journeySpec.")

    return pruned, warnings


def _normalize_type(value: Any, mapping: dict, warnings: List[str], label: str) -> Any:
    if not isinstance(value, str):
        return value
    key = value.strip()
    if not key:
        return value
    mapped = mapping.get(key.lower())
    if mapped and mapped != value:
        warnings.append(f"Normalized {label} type '{value}' to '{mapped}'.")
        return mapped
    return value


def _normalize_wait_unit(value: Any, warnings: List[str]) -> Any:
    if not isinstance(value, str):
        return value
    key = value.strip().lower()
    if not key:
        return value
    mapping = {
        "minutes": "MINUTES",
        "minute": "MINUTES",
        "mins": "MINUTES",
        "min": "MINUTES",
        "hours": "HOURS",
        "hour": "HOURS",
        "hrs": "HOURS",
        "hr": "HOURS",
        "days": "DAYS",
        "day": "DAYS",
        "weeks": "WEEKS",
        "week": "WEEKS",
    }
    mapped = mapping.get(key)
    if mapped and mapped != value:
        warnings.append(f"Normalized waitUnit '{value}' to '{mapped}'.")
        return mapped
    return value


def _merge_configuration_arguments(item: dict, warnings: List[str], label: str) -> None:
    args = item.get("arguments")
    cfg = item.get("configurationArguments")
    args_dict = args if isinstance(args, dict) else None
    cfg_dict = cfg if isinstance(cfg, dict) else None

    if args is not None and args_dict is None:
        warnings.append(f"Ignored non-object arguments for {label}.")

    if cfg is not None and cfg_dict is None:
        warnings.append(f"Ignored non-object configurationArguments for {label}.")

    if cfg_dict is None and args_dict is not None:
        item["configurationArguments"] = dict(args_dict)
        item["arguments"] = dict(args_dict)
        warnings.append(f"Copied {label} arguments to configurationArguments.")
        return

    if cfg_dict is not None and args_dict is not None:
        merged = dict(args_dict)
        merged.update(cfg_dict)
        item["arguments"] = dict(merged)
        item["configurationArguments"] = dict(merged)
        warnings.append(f"Merged {label} arguments into configurationArguments.")
        return

    if cfg_dict is not None and args_dict is None:
        item["configurationArguments"] = dict(cfg_dict)
        item["arguments"] = dict(cfg_dict)
        warnings.append(f"Copied {label} configurationArguments to arguments.")
        return

    if cfg_dict is None:
        item["configurationArguments"] = {}
        item["arguments"] = {}


def _normalize_journey_spec(spec: dict, warnings: List[str]) -> dict:
    if not isinstance(spec, dict):
        return spec

    if "workflowApiVersion" in spec and not isinstance(spec.get("workflowApiVersion"), str):
        spec["workflowApiVersion"] = str(spec.get("workflowApiVersion"))
        warnings.append("Coerced workflowApiVersion to string.")

    if not spec.get("definitionType"):
        spec["definitionType"] = "Multistep"
        warnings.append("Added default definitionType 'Multistep'.")

    if not spec.get("entryMode"):
        spec["entryMode"] = "SingleEntryAcrossAllVersions"
        warnings.append("Added default entryMode 'SingleEntryAcrossAllVersions'.")

    trigger_type_map = {
        "event": "Event",
    }
    activity_type_map = {
        "wait": "WAIT",
        "email": "EMAIL",
        "emailv2": "EMAILV2",
        "engagementsplit": "ENGAGEMENTSPLIT",
        "updatecontact": "UPDATECONTACT",
    }

    triggers = spec.get("triggers")
    if isinstance(triggers, list):
        for idx, trigger in enumerate(triggers, start=1):
            if not isinstance(trigger, dict):
                warnings.append(f"Ignored non-object trigger at index {idx}.")
                continue
            if not trigger.get("key"):
                trigger["key"] = f"TRIGGER_{idx}"
                warnings.append(f"Added missing trigger key 'TRIGGER_{idx}'.")
            if not trigger.get("name"):
                trigger["name"] = trigger.get("key")
                warnings.append(f"Added missing trigger name '{trigger.get('name')}'.")
            trigger["type"] = _normalize_type(trigger.get("type"), trigger_type_map, warnings, "trigger")
            _merge_configuration_arguments(trigger, warnings, f"trigger '{trigger.get('key')}'")
            _normalize_trigger_configuration(trigger, warnings)

    activities = spec.get("activities")
    if isinstance(activities, list):
        for idx, activity in enumerate(activities, start=1):
            if not isinstance(activity, dict):
                warnings.append(f"Ignored non-object activity at index {idx}.")
                continue
            if not activity.get("key"):
                activity["key"] = f"ACTIVITY_{idx}"
                warnings.append(f"Added missing activity key 'ACTIVITY_{idx}'.")
            if not activity.get("name"):
                activity["name"] = activity.get("key")
                warnings.append(f"Added missing activity name '{activity.get('name')}'.")
            activity["type"] = _normalize_type(activity.get("type"), activity_type_map, warnings, "activity")
            _merge_configuration_arguments(activity, warnings, f"activity '{activity.get('key')}'")

            cfg = activity.get("configurationArguments")
            if isinstance(cfg, dict) and "waitUnit" in cfg:
                cfg["waitUnit"] = _normalize_wait_unit(cfg.get("waitUnit"), warnings)

            _normalize_activity_configuration(activity, warnings)

    return spec


def _ensure_default_outcomes(spec: dict, warnings: List[str]) -> dict:
    """
    Ensure triggers + activities have basic outcomes wired in sequence when outcomes are missing.

    This helps Journey Builder render the canvas when callers omit explicit wiring.
    """
    if not isinstance(spec, dict):
        return spec

    activities = spec.get("activities")
    if not isinstance(activities, list) or not activities:
        return spec

    activity_keys: List[str] = []
    for idx, activity in enumerate(activities, start=1):
        if not isinstance(activity, dict):
            continue
        key = activity.get("key")
        if not key:
            key = f"AUTO_ACTIVITY_{idx}"
            activity["key"] = key
            warnings.append(f"Added missing activity key '{key}'.")
        activity_keys.append(key)

    if not activity_keys:
        return spec

    triggers = spec.get("triggers")
    if isinstance(triggers, list):
        for trigger in triggers:
            if not isinstance(trigger, dict):
                continue
            outcomes = trigger.get("outcomes")
            if not isinstance(outcomes, list) or not outcomes:
                trigger["outcomes"] = [{"next": activity_keys[0]}]
                warnings.append("Added default trigger outcome to first activity.")

    for idx, activity in enumerate(activities):
        if not isinstance(activity, dict):
            continue
        outcomes = activity.get("outcomes")
        if isinstance(outcomes, list) and outcomes:
            continue
        next_key = activity_keys[idx + 1] if idx + 1 < len(activity_keys) else None
        if next_key:
            activity["outcomes"] = [{"next": next_key}]
            warnings.append(
                f"Added default outcome from activity '{activity.get('key')}' to '{next_key}'."
            )
        else:
            activity["outcomes"] = []
            warnings.append(f"Added empty outcomes for terminal activity '{activity.get('key')}'.")

    return spec


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _normalize_trigger_configuration(trigger: dict, warnings: List[str]) -> None:
    cfg = trigger.get("configurationArguments")
    if not isinstance(cfg, dict):
        return
    if "eventDefinitionKey" not in cfg:
        legacy = trigger.get("eventDefinitionKey") or trigger.get("eventDefinitionId")
        if legacy:
            cfg["eventDefinitionKey"] = legacy
            trigger["arguments"]["eventDefinitionKey"] = legacy
            warnings.append(
                f"Moved trigger '{trigger.get('key')}' eventDefinitionKey into configurationArguments."
            )


def _normalize_activity_configuration(activity: dict, warnings: List[str]) -> None:
    cfg = activity.get("configurationArguments")
    if not isinstance(cfg, dict):
        return

    activity_type = (activity.get("type") or "").upper()

    if activity_type == "WAIT":
        if cfg.get("waitDuration") is None:
            cfg["waitDuration"] = 1
            warnings.append(
                f"Added default waitDuration=1 for activity '{activity.get('key')}'."
            )
        if not cfg.get("waitUnit"):
            cfg["waitUnit"] = "DAYS"
            warnings.append(
                f"Added default waitUnit 'DAYS' for activity '{activity.get('key')}'."
            )
        cfg["waitUnit"] = _normalize_wait_unit(cfg.get("waitUnit"), warnings)

    if activity_type == "EMAIL":
        if cfg.get("emailAssetId") and not cfg.get("emailId"):
            activity["type"] = "EMAILV2"
            warnings.append(
                f"Upgraded activity '{activity.get('key')}' to EMAILV2 because emailAssetId is present."
            )
            activity_type = "EMAILV2"

    if activity_type == "EMAILV2":
        email_asset_id = _coerce_int(cfg.get("emailAssetId"))
        if email_asset_id is not None:
            cfg["emailAssetId"] = email_asset_id
        if cfg.get("emailAssetId") and not cfg.get("emailAssetName"):
            cfg["emailAssetName"] = activity.get("name")
            warnings.append(
                f"Added emailAssetName for activity '{activity.get('key')}'."
            )
        if cfg.get("emailId") and not cfg.get("emailAssetId"):
            activity["type"] = "EMAIL"
            warnings.append(
                f"Downgraded activity '{activity.get('key')}' to EMAIL because emailId is present."
            )

    if activity_type == "ENGAGEMENTSPLIT":
        if not cfg.get("criteria"):
            cfg["criteria"] = "Open"
            warnings.append(
                f"Added default engagement criteria 'Open' for activity '{activity.get('key')}'."
            )

        outcomes = activity.get("outcomes")
        if isinstance(outcomes, list) and len(outcomes) == 1:
            outcomes.append({}) # Add a default 'No' path that exits the journey
            warnings.append(
                f"Added default 'No' path (exit) outcome for engagement split activity '{activity.get('key')}'."
            )

    if activity_type == "UPDATECONTACT":
        if not cfg.get("updateFields"):
            cfg["updateFields"] = [
                {"fieldName": "LastUpdated", "value": "Now()"}
            ]
            warnings.append(
                f"Added default updateFields for activity '{activity.get('key')}'."
            )
        else:
            fields = cfg.get("updateFields")
            if isinstance(fields, list):
                for f in fields:
                    if isinstance(f, dict):
                        val = f.get("value")
                        if isinstance(val, str) and val.lower() == "getdate":
                            f["value"] = "Now()"
                            warnings.append(
                                f"Normalized updateFields value 'getdate' to 'Now()' for activity '{activity.get('key')}'."
                            )

        if cfg.get("dataExtensionName") and not cfg.get("dataExtensionKey"):
            cfg["dataExtensionKey"] = cfg.get("dataExtensionName")
            warnings.append(
                f"Copied dataExtensionName to dataExtensionKey for activity '{activity.get('key')}'."
            )


def _extract_journey_spec(params: dict) -> Tuple[Optional[dict], List[str]]:
    """
    Accept either:
      - params.journeySpec (preferred), or
      - top-level fields: key,name,workflowApiVersion,triggers,activities,description,...
    """
    warnings: List[str] = []
    if not isinstance(params, dict):
        return None, ["Params not an object"]

    # Preferred nested
    js = params.get("journeySpec")
    if isinstance(js, dict):
        pruned, w = _prune_server_fields(js)
        warnings.extend(w)
        pruned = _normalize_journey_spec(pruned, warnings)
        pruned = _ensure_default_outcomes(pruned, warnings)
        return pruned, warnings

    # Alias: "spec"
    js2 = params.get("spec")
    if isinstance(js2, dict):
        pruned, w = _prune_server_fields(js2)
        warnings.extend(w)
        pruned = _normalize_journey_spec(pruned, warnings)
        pruned = _ensure_default_outcomes(pruned, warnings)
        return pruned, warnings

    # Build from top-level fields
    spec = {}
    for k in ["key", "name", "description", "workflowApiVersion", "triggers", "activities", "goals"]:
        if k in params:
            spec[k] = params.get(k)

    if not spec:
        return None, ["Missing journeySpec (or top-level key/name/workflowApiVersion/triggers/activities)."]

    pruned, w = _prune_server_fields(spec)
    warnings.extend(w)
    pruned = _normalize_journey_spec(pruned, warnings)
    pruned = _ensure_default_outcomes(pruned, warnings)
    return pruned, warnings


def _validate_for_create(spec: dict) -> Tuple[bool, List[str], List[str]]:
    """
    Minimal validation aligned to Create Interaction requirements:
      required: key, name, workflowApiVersion, triggers, activities
    We don't enforce deep Journey Spec correctness (that belongs to your orchestrator/plan builder).
    """
    missing = []
    errors = []

    if not isinstance(spec, dict):
        return False, ["journeySpec"], ["journeySpec must be an object"]

    if not spec.get("key"):
        missing.append("key")
    elif not _validate_uuid(spec.get("key")):
        errors.append("key must be a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")

    if not spec.get("name"):
        missing.append("name")

    if not spec.get("workflowApiVersion"):
        missing.append("workflowApiVersion")

    tr = spec.get("triggers")
    if tr is None:
        missing.append("triggers")
    elif not isinstance(tr, list):
        errors.append("triggers must be an array")
    else:
        if len(tr) > MAX_TRIGGERS:
            errors.append(f"triggers exceeds MAX_TRIGGERS ({MAX_TRIGGERS})")

    act = spec.get("activities")
    if act is None:
        missing.append("activities")
    elif not isinstance(act, list):
        errors.append("activities must be an array")
    else:
        if len(act) > MAX_ACTIVITIES:
            errors.append(f"activities exceeds MAX_ACTIVITIES ({MAX_ACTIVITIES})")

    # size guard
    try:
        b = json.dumps(spec).encode("utf-8")
        if len(b) > MAX_SPEC_BYTES:
            errors.append(f"journeySpec size {len(b)} bytes exceeds MAX_SPEC_BYTES ({MAX_SPEC_BYTES})")
    except Exception:
        errors.append("journeySpec could not be JSON-serialized")

    ok = (len(missing) == 0 and len(errors) == 0)
    return ok, missing, errors


def _check_runtime_config() -> Tuple[bool, dict]:
    missing = []
    if not SFMC_SECRET_REF:
        missing.append("SFMC_SECRET_ARN|SFMC_SECRET_ID")
    if not SFMC_ENV:
        missing.append("SFMC_ENV")

    if SFMC_ENV != REQUIRED_SFMC_ENV:
        return False, {
            "status": "FAIL",
            "sfmcEnv": SFMC_ENV or None,
            "requiredEnv": REQUIRED_SFMC_ENV,
            "missingEnv": missing,
            "message": f"Sandbox guardrail blocked execution. Set SFMC_ENV={REQUIRED_SFMC_ENV}.",
        }

    if missing:
        return False, {
            "status": "FAIL",
            "sfmcEnv": SFMC_ENV or None,
            "requiredEnv": REQUIRED_SFMC_ENV,
            "missingEnv": missing,
            "message": "Missing required runtime configuration.",
        }

    return True, {
        "status": "PASS",
        "sfmcEnv": SFMC_ENV,
        "requiredEnv": REQUIRED_SFMC_ENV,
        "missingEnv": [],
        "hostSuffixGuardrailEnforced": bool(SFMC_ALLOWED_HOST_SUFFIXES),
        "hostSuffixAllowlist": SFMC_ALLOWED_HOST_SUFFIXES,
        "accountGuardrailEnforced": bool(SFMC_ALLOWED_ACCOUNT_ID),
    }


# -----------------------------
# Handlers
# -----------------------------
def handle_healthz() -> Tuple[int, dict]:
    ok, details = _check_runtime_config()
    return 200, {
        "ok": True,
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "runtime": details,
        "healthzOk": bool(ok),
    }


def build_journey_draft(params: dict) -> Tuple[int, dict]:
    t0 = _perf_ms()
    requested_inputs_raw = dict(params or {})
    requested_inputs = _sanitize_requested_inputs(requested_inputs_raw)

    # Parse booleans
    create_in_sfmc_raw = requested_inputs_raw.get("createInSfmc")
    dry_run_raw = requested_inputs_raw.get("dryRun")
    force_refresh_raw = requested_inputs_raw.get("forceTokenRefresh")

    create_in_sfmc, ok1 = _to_bool_strict(create_in_sfmc_raw, default=False)
    if not ok1:
        return 400, {"ok": False, "error": "BadRequest", "message": "createInSfmc must be boolean"}

    if dry_run_raw is None:
        dry_run = DRY_RUN_DEFAULT
    else:
        dry_run, ok2 = _to_bool_strict(dry_run_raw, default=DRY_RUN_DEFAULT)
        if not ok2:
            return 400, {"ok": False, "error": "BadRequest", "message": "dryRun must be boolean"}

    force_refresh, ok3 = _to_bool_strict(force_refresh_raw, default=False)
    if not ok3:
        return 400, {"ok": False, "error": "BadRequest", "message": "forceTokenRefresh must be boolean"}

    # Extract spec
    spec, spec_warnings = _extract_journey_spec(requested_inputs_raw)
    if not spec:
        return 400, {
            "ok": False,
            "error": "BadRequest",
            "message": "Missing journeySpec (or top-level key/name/workflowApiVersion/triggers/activities).",
        }

    valid_for_create, missing, errors = _validate_for_create(spec)

    # Runtime guardrail (always enforced before any SFMC call)
    runtime_ok, runtime_details = _check_runtime_config()
    if not runtime_ok and create_in_sfmc and not dry_run:
        return 400, {
            "ok": False,
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "error": "GuardrailBlocked",
            "message": runtime_details.get("message"),
            "runtime": runtime_details,
            "validation": {"validForCreate": valid_for_create, "missingRequiredForCreate": missing, "errors": errors},
        }

    # If caller asked to create, but validation fails, block create (even if dryRun=false)
    if create_in_sfmc and not dry_run and not valid_for_create:
        return 400, {
            "ok": False,
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "error": "InvalidJourneySpec",
            "message": "journeySpec missing required fields for createInteraction.",
            "validation": {"validForCreate": False, "missingRequiredForCreate": missing, "errors": errors},
            "warnings": spec_warnings,
        }

    create_attempted = False
    create_result = None
    sfmc_evidence = {}

    # Optionally create in SFMC (draft journey)
    if create_in_sfmc and not dry_run:
        create_attempted = True

        access_token, rest_base, auth_base, meta = _get_access_token(force_refresh=force_refresh)
        sfmc_evidence = {
            "authHost": _host_from_url(auth_base),
            "restHost": _host_from_url(rest_base),
            "accountId": meta.get("accountId"),
            "tokenCacheHit": meta.get("tokenCacheHit"),
        }

        # Host allowlist check (defensive)
        if SFMC_ALLOWED_HOST_SUFFIXES:
            if not _host_allowed(sfmc_evidence.get("authHost")) or not _host_allowed(sfmc_evidence.get("restHost")):
                return 400, {
                    "ok": False,
                    "error": "HostSuffixGuardrailFailed",
                    "message": "SFMC host suffix guardrail failed.",
                    "evidence": sfmc_evidence,
                    "allowlist": SFMC_ALLOWED_HOST_SUFFIXES,
                }

        url = f"{rest_base}/interaction/v1/interactions"
        headers = _sfmc_headers(access_token)

        logger.info("SENDING_TO_SFMC_API url=%s payload=%s", url, json.dumps(spec))

        t_call = _perf_ms()
        status, body = _http_json("POST", url, headers=headers, payload=spec, timeout=REST_TIMEOUT)
        dur = int(_perf_ms() - t_call)

        create_result = {
            "httpStatus": status,
            "durationMs": dur,
            "response": body,
        }

        if status < 200 or status >= 300:
            return 502, {
                "ok": False,
                "tool": TOOL_NAME,
                "toolVersion": TOOL_VERSION,
                "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
                "error": "SfmcCreateFailed",
                "message": "SFMC create interaction call failed.",
                "sfmc": create_result,
                "evidence": sfmc_evidence,
                "validation": {"validForCreate": valid_for_create, "missingRequiredForCreate": missing, "errors": errors},
                "warnings": spec_warnings,
            }

    out = {
        "ok": True,
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "timestampUtc": _now_utc_iso(),
        "sfmcEnv": SFMC_ENV or None,
        "runtime": runtime_details,
        "requestedInputs": requested_inputs,
        "effectiveInputs": {
            "createInSfmc": bool(create_in_sfmc),
            "dryRun": bool(dry_run),
            "forceTokenRefresh": bool(force_refresh),
        },
        "validation": {
            "validForCreate": bool(valid_for_create),
            "missingRequiredForCreate": missing,
            "errors": errors,
        },
        "warnings": spec_warnings,
        "journeySpec": spec,
        "createAttempted": bool(create_attempted),
        "sfmcCreateResult": create_result,
        "evidence": sfmc_evidence,
        "timings": {"totalMs": int(_perf_ms() - t0)},
        "hints": [
            "Default is dryRun=true; set createInSfmc=true and dryRun=false to POST to SFMC.",
            "Create requires the Journey Spec minimum: key,name,workflowApiVersion,triggers,activities. "
            "Deep correctness (activity configs, outcomes, eventDefinitionKey, etc.) is up to your orchestrator/plan.",
        ],
    }
    return 200, out


def lambda_handler(event, context):
    api_path = _get_api_path(event).lower()
    method = _get_http_method(event).upper()

    if not api_path:
        api_path = "/journeydraft"

    bedrock = bool(isinstance(event, dict) and _is_bedrock_event(event))

    try:
        logger.info("Incoming event keys: %s", list(event.keys()) if isinstance(event, dict) else type(event))
        logger.info("Resolved route: %s %s", method, api_path)
    except Exception:
        pass

    # Route/method validation
    if not _is_supported_route(method, api_path):
        allowed = _allowed_methods_for_path(api_path)
        if allowed:
            status_code = 405
            err = "MethodNotAllowed"
            msg = f"Method not allowed for path: {method} {api_path}"
        else:
            status_code = 404
            err = "NotFound"
            msg = f"Unknown path: {method} {api_path}"

        payload = {
            "ok": False,
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "error": err,
            "message": msg,
            "supported": {m: sorted(list(paths)) for m, paths in SUPPORTED_ROUTES.items()},
            "allowedMethods": allowed or None,
        }
        return _bedrock_actiongroup_response(event, payload, http_code=status_code) if bedrock else _json_response(payload, status_code)

    try:
        # GET /healthz
        if api_path == "/healthz" and method == "GET":
            status, body = handle_healthz()
            return _bedrock_actiongroup_response(event, body, http_code=status) if bedrock else _json_response(body, status)

        # POST /journeydraft (and aliases)
        if api_path in ("/journeydraft", "/journey-draft", "/draft") and method == "POST":
            params = _parse_json_body(event) or {}
            status, body = build_journey_draft(params)
            return _bedrock_actiongroup_response(event, body, http_code=status) if bedrock else _json_response(body, status)

        # Defensive fallback
        payload = {
            "ok": False,
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "error": "BadRequest",
            "message": f"Unsupported route: {method} {api_path}",
        }
        return _bedrock_actiongroup_response(event, payload, http_code=400) if bedrock else _json_response(payload, 400)

    except Exception as e:
        err = str(e)
        logger.exception("Unhandled error")
        payload = {
            "ok": False,
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "error": "UnhandledError",
            "message": err,
        }
        return _bedrock_actiongroup_response(event, payload, http_code=500) if bedrock else _json_response(payload, 500)
