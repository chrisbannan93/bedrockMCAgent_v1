import os
import json
import time
import logging
import base64
from typing import Any, Dict, Optional, Tuple, List
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import boto3

# -----------------------------
# Tool metadata
# -----------------------------
TOOL_NAME = "sfmc_health_report"
TOOL_VERSION = "2025-12-18"
OUTPUT_SCHEMA_VERSION = "1.3.4"  # bumped: route/method validation using SUPPORTED_ROUTES

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Config / Guardrails
# -----------------------------
REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "20"))
SOAP_TIMEOUT = int(os.getenv("SOAP_TIMEOUT", "20"))

# Sandbox guardrail
SFMC_ENV = (os.getenv("SFMC_ENV") or "").strip().lower()
REQUIRED_SFMC_ENV = (os.getenv("SFMC_REQUIRED_ENV") or "sandbox").strip().lower()

# Optional BU/account guardrail (recommended)
SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

# Optional host allowlist guardrail (recommended)
# Comma-separated host suffixes, e.g.:
#   marketingcloudapis.com, exacttarget.com
SFMC_ALLOWED_HOST_SUFFIXES = [
    s.strip().lower()
    for s in (os.getenv("SFMC_ALLOWED_HOST_SUFFIXES") or "").split(",")
    if s.strip()
]

# Secret reference (required)
SFMC_SECRET_REF = (os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or "").strip()

# Optional base URLs (can be derived from auth url or token response)
SFMC_AUTH_BASE_URL = (os.getenv("SFMC_AUTH_BASE_URL") or "").strip()
SFMC_REST_BASE_URL = (os.getenv("SFMC_REST_BASE_URL") or "").strip()
SFMC_SOAP_BASE_URL = (os.getenv("SFMC_SOAP_BASE_URL") or "").strip()

# Keep routes aligned with OpenAPI: /healthReport, /health, /report and /healthz
SUPPORTED_ROUTES = {
    "GET": {"/healthz", "/healthreport", "/health", "/report"},
    "POST": {"/healthreport", "/health", "/report"},
}

ALLOWED_MODES = {"quick", "configonly", "coldstart"}
_BOOL_TRUE = {"true", "1", "yes", "y", "on"}
_BOOL_FALSE = {"false", "0", "no", "n", "off"}


def _supported_routes_payload() -> dict:
    return {m: sorted(list(paths)) for m, paths in SUPPORTED_ROUTES.items()}


def _allowed_methods_for_path(path_lower: str) -> List[str]:
    p = (path_lower or "").strip().lower()
    if not p:
        return []
    allowed = []
    for m, paths in SUPPORTED_ROUTES.items():
        if p in paths:
            allowed.append(m)
    return sorted(allowed)


def _is_supported_route(method_upper: str, path_lower: str) -> bool:
    m = (method_upper or "").strip().upper()
    p = (path_lower or "").strip().lower()
    return bool(m and p and (m in SUPPORTED_ROUTES) and (p in SUPPORTED_ROUTES[m]))


# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,  # epoch seconds
    "rest_base_url": None,
    "soap_base_url": None,
    "auth_base_url": None,
    "account_id": None,
}


def _reset_token_cache() -> None:
    _TOKEN_CACHE["access_token"] = None
    _TOKEN_CACHE["expires_at"] = 0
    _TOKEN_CACHE["rest_base_url"] = None
    _TOKEN_CACHE["soap_base_url"] = None
    _TOKEN_CACHE["auth_base_url"] = None
    _TOKEN_CACHE["account_id"] = None


# -----------------------------
# Utilities
# -----------------------------
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_base(url: str) -> str:
    url = (url or "").strip()
    return url[:-1] if url.endswith("/") else url


def _ensure_scheme(url: str, default_scheme: str = "https") -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return f"{default_scheme}://{u}"


def _url_base_only(url: str) -> str:
    """
    Converts a URL (possibly including path/query/fragment) into scheme://host[:port]
    while preserving explicit scheme if present. If schemeless, assumes https.
    """
    u = _ensure_scheme(url)
    p = urlparse(u)
    scheme = p.scheme or "https"
    netloc = p.netloc
    # If user passed something like "example.com/path" without scheme, urlparse puts it in path.
    if not netloc and p.path:
        netloc = p.path.split("/", 1)[0]
    return f"{scheme}://{netloc}" if netloc else ""


def _strip_known_auth_paths(auth_url_or_base: str) -> str:
    """
    SFMC secrets sometimes store a full token URL (e.g., .../v2/token) instead of a base.
    Normalize to base host-only URL.
    """
    base = _url_base_only(auth_url_or_base)
    if not base:
        return ""
    # base is already host-only; nothing else to strip
    return _norm_base(base)


def _swap_host_segment(url_base: str, old: str, new: str) -> str:
    """
    Replace a segment in the host portion of a URL base.
    Example: https://xxx.auth.marketingcloudapis.com -> https://xxx.rest.marketingcloudapis.com
    """
    u = _ensure_scheme(url_base)
    p = urlparse(u)
    scheme = p.scheme or "https"
    netloc = p.netloc or ""
    if not netloc and p.path:
        netloc = p.path.split("/", 1)[0]
    if not netloc:
        return ""
    swapped = netloc.replace(old, new)
    return f"{scheme}://{swapped}"


def _json_response(body_obj: dict, status_code: int = 200) -> dict:
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }


def _is_bedrock_event(event: dict) -> bool:
    # Bedrock action group events generally include messageVersion and do not include "response" yet
    return "messageVersion" in event and "response" not in event


def _normalize_api_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return ""
    p = "/" + p.lstrip("/")
    return p.rstrip("/")


def _get_api_path(event: dict) -> str:
    p = event.get("apiPath")
    if p:
        return _normalize_api_path(p)

    agi = event.get("actionGroupInvocationInput", {}) or {}
    p2 = agi.get("apiPath")
    if p2:
        return _normalize_api_path(p2)

    # API Gateway / ALB / other shapes
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

    # HTTP API shape
    rc = event.get("requestContext", {}) or {}
    http = rc.get("http", {}) or {}
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


def _perf_ms() -> float:
    return time.perf_counter() * 1000.0


def _to_bool(v: Any, default: bool = True) -> bool:
    """
    Lenient boolean coercion (used only where caller expects coercion).
    """
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in _BOOL_TRUE:
        return True
    if s in _BOOL_FALSE:
        return False
    return default


def _to_bool_strict(v: Any, default: bool) -> Tuple[bool, bool]:
    """
    Strict boolean parsing:
      returns (value, ok)
      ok=False when caller supplied a non-boolean, non-coercible value
    """
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


def _unwrap_bedrock_scalar(v: Any) -> Any:
    """
    Some runtimes may wrap values as dicts like {"stringValue":"x"} or {"booleanValue":true}.
    Normalize those into raw scalars where possible.
    """
    if isinstance(v, dict) and v:
        for k in ("stringValue", "booleanValue", "intValue", "integerValue", "doubleValue", "floatValue", "value"):
            if k in v:
                return v.get(k)
    return v


def _coerce_bedrock_value(v: Any, declared_type: Optional[str]) -> Any:
    """
    Bedrock Action Group often sends {"name":..., "type":"boolean", "value":"false"}.
    Coerce based on declared_type where possible.
    """
    v = _unwrap_bedrock_scalar(v)
    t = (declared_type or "").strip().lower()

    if t == "boolean":
        # coerce known truthy/falsey strings safely
        return _to_bool(v, default=False)
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
    """
    Parses Bedrock-style lists like:
      [{"name":"includeSoapProbe","type":"boolean","value":"false"}, ...]
    """
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


def _parse_query_params(event: dict) -> dict:
    """
    API Gateway style query string params. Useful for GET /healthReport?mode=configOnly etc.
    Also supports multiValueQueryStringParameters, and actionGroupInvocationInput.queryStringParameters.
    """
    # 1) Standard
    q = event.get("queryStringParameters") or {}
    if isinstance(q, dict) and q:
        return {str(k): v for k, v in q.items() if k is not None and v is not None}

    # 2) Multi-value
    mv = event.get("multiValueQueryStringParameters") or {}
    if isinstance(mv, dict) and mv:
        out = {}
        for k, v in mv.items():
            if k is None or v is None:
                continue
            if isinstance(v, list) and v:
                out[str(k)] = v[0]
            else:
                out[str(k)] = v
        return out

    # 3) Bedrock wrapper (defensive)
    agi = event.get("actionGroupInvocationInput", {}) or {}
    q2 = agi.get("queryStringParameters") or {}
    if isinstance(q2, dict) and q2:
        return {str(k): v for k, v in q2.items() if k is not None and v is not None}

    return {}


def _maybe_json_loads(s: str) -> Any:
    """
    Safe JSON parse that returns None on failure.
    """
    try:
        return json.loads(s)
    except Exception:
        return None


def _maybe_decode_body(event: dict) -> Optional[str]:
    """
    API Gateway may send base64-encoded bodies.
    """
    b = event.get("body")
    if b is None:
        return None
    if isinstance(b, dict):
        # caller handles dict body directly
        return None
    if not isinstance(b, str):
        return None
    if not b.strip():
        return ""
    if event.get("isBase64Encoded") is True:
        try:
            decoded = base64.b64decode(b).decode("utf-8")
            return decoded
        except Exception:
            # fall back to raw string
            return b
    return b


def _parse_json_body(event: dict) -> dict:
    """
    Supports:
      - Direct invoke (Lambda Console): event itself contains param keys (mode/includeRestProbes/etc.)
      - Standard invoke: event["body"] as JSON string/dict (also supports base64 encoding)
      - Bedrock action group: event.actionGroupInvocationInput.requestBody.content.application/json
        where application/json may be:
          a) {"body":"{...}"}  OR
          b) {"body":[{name,type,value}, ...]} OR
          c) a dict body itself OR
          d) a list of {name,type,value} entries  (COMMON)
          e) {"body":"[{name,type,value}, ...]"} (COMMON)
      - Bedrock action group parameters: event.actionGroupInvocationInput.parameters (list of name/value/type)
    """
    # 0) Direct invoke convenience (Lambda Console "event" is the params dict)
    # Only apply if it doesn't look like an API Gateway/Bedrock event.
    direct_block_keys = {
        "body", "requestContext", "actionGroupInvocationInput", "httpMethod", "rawPath", "path", "apiPath",
        "headers", "queryStringParameters", "routeKey", "version", "requestBody", "messageVersion"
    }
    param_keys = {
        "mode",
        "includeRestProbes", "includeRestProbe", "includeRest",
        "includeSoapProbe", "includeSoap",
        "forceTokenRefresh", "forceAuthRefresh", "simulateColdStart",
    }
    if isinstance(event, dict) and not any(k in event for k in direct_block_keys):
        if any(k in event for k in param_keys):
            return {k: event[k] for k in param_keys if k in event}

    # 1) Standard Lambda/API GW "body"
    b_dict = event.get("body")
    if isinstance(b_dict, dict):
        return b_dict

    b_str = _maybe_decode_body(event)
    if isinstance(b_str, str) and b_str.strip():
        parsed = _maybe_json_loads(b_str)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            # allow list-of-kv entries in plain "body"
            kv = _parse_actiongroup_kv_list(parsed)
            return kv if isinstance(kv, dict) else {}
        return {}

    # 2) Bedrock action group: requestBody + parameters
    agi = (event.get("actionGroupInvocationInput", {}) or {})
    params_from_agi = _parse_actiongroup_kv_list(agi.get("parameters") or event.get("parameters"))

    rb = event.get("requestBody") or agi.get("requestBody") or {}
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        aj = content.get("application/json") or content.get("application_json")

        # application/json can sometimes be a JSON string
        if isinstance(aj, str) and aj.strip():
            aj_parsed = _maybe_json_loads(aj)
            if isinstance(aj_parsed, (dict, list)):
                aj = aj_parsed

        # Case: application/json directly a list of kv entries
        if isinstance(aj, list):
            body_params = _parse_actiongroup_kv_list(aj)
            merged = dict(params_from_agi)
            merged.update(body_params)
            return merged

        # Case: application/json is a dict wrapper
        if isinstance(aj, dict):
            body = aj.get("body")

            # If wrapper body is already kv-list
            if isinstance(body, list):
                body_params = _parse_actiongroup_kv_list(body)
                merged = dict(params_from_agi)
                merged.update(body_params)
                return merged

            # If wrapper body is dict
            if isinstance(body, dict):
                merged = dict(params_from_agi)
                merged.update(body)
                return merged

            # If wrapper body is a JSON string (dict OR list)
            if isinstance(body, str) and body.strip():
                parsed_body = _maybe_json_loads(body)
                if isinstance(parsed_body, dict):
                    merged = dict(params_from_agi)
                    merged.update(parsed_body)
                    return merged
                if isinstance(parsed_body, list):
                    body_params = _parse_actiongroup_kv_list(parsed_body)
                    merged = dict(params_from_agi)
                    merged.update(body_params)
                    return merged

            # Otherwise: merge wrapper keys (excluding "body" if it's not useful)
            merged = dict(params_from_agi)
            for k, v in aj.items():
                if k == "body":
                    continue
                merged[k] = v
            return merged

    # 3) If only parameters were provided
    return dict(params_from_agi)


def _sanitize_requested_inputs(d: dict) -> dict:
    """
    Avoid echoing back accidental secrets. We keep structure, but redact obvious fields.
    """
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


def _first_present(d: dict, keys: List[str]) -> Tuple[Optional[str], Any]:
    for k in keys:
        if k in d:
            return k, d.get(k)
    return None, None


# -----------------------------
# HTTP helpers (REST + SOAP)
# -----------------------------
def _http_json(
    method: str,
    url: str,
    headers: dict,
    payload: Optional[dict] = None,
    timeout: int = REST_TIMEOUT,
) -> Tuple[int, dict]:
    data = None
    h = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        h["Content-Type"] = "application/json"
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


SOAPENV_NS_11 = "http://schemas.xmlsoap.org/soap/envelope/"
PARTNER_NS = "http://exacttarget.com/wsdl/partnerAPI"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"


def _http_soap(url: str, soap_xml: str, timeout: int = SOAP_TIMEOUT) -> Tuple[int, str]:
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "Retrieve",
        "Accept": "text/xml",
    }
    data = soap_xml.encode("utf-8")
    req = Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, raw
    except HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8") if e.fp else ""
        except Exception:
            raw = ""
        return e.code, raw or str(e)
    except URLError as e:
        return 599, f"URLError: {e}"


def _local(tag: str) -> str:
    if not tag:
        return ""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _soap_fault_summary(xml_text: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None
    body = root.find(f".//{{{SOAPENV_NS_11}}}Body")
    if body is None:
        return None
    fault = None
    for el in body.iter():
        if _local(el.tag) == "Fault":
            fault = el
            break
    if fault is None:
        return None
    faultcode = None
    faultstring = None
    for ch in list(fault):
        nm = _local(ch.tag)
        if nm == "faultcode":
            faultcode = (ch.text or "").strip()
        if nm == "faultstring":
            faultstring = (ch.text or "").strip()
    if faultcode or faultstring:
        return f"{faultcode or ''} {faultstring or ''}".strip()
    return "SOAP Fault returned"


def _soap_envelope(fueloauth: str, body_inner_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS_11}" xmlns:xsi="{XSI_NS}">
  <soapenv:Header>
    <fueloauth>{fueloauth}</fueloauth>
  </soapenv:Header>
  <soapenv:Body>
    {body_inner_xml}
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_simple_filter(property_name: str, operator: str, value: str) -> str:
    return f"""
<Filter xsi:type="SimpleFilterPart">
  <Property>{property_name}</Property>
  <SimpleOperator>{operator}</SimpleOperator>
  <Value>{value}</Value>
</Filter>"""


def _soap_retrieve_request_xml(object_type: str, properties: list, filter_xml: Optional[str] = None) -> str:
    props_xml = "\n".join([f"<Properties>{p}</Properties>" for p in properties])
    fxml = filter_xml or ""
    return f"""
<RetrieveRequestMsg xmlns="{PARTNER_NS}">
  <RetrieveRequest>
    <ObjectType>{object_type}</ObjectType>
    {props_xml}
    {fxml}
  </RetrieveRequest>
</RetrieveRequestMsg>"""


def _soap_overall_status(xml_text: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None, None
    body = root.find(f".//{{{SOAPENV_NS_11}}}Body")
    if body is None:
        return None, None
    rrm = None
    for el in body.iter():
        if _local(el.tag) == "RetrieveResponseMsg":
            rrm = el
            break
    if rrm is None:
        return None, None
    overall = None
    msg = None
    for child in list(rrm):
        nm = _local(child.tag)
        if nm == "OverallStatus":
            overall = (child.text or "").strip()
        if nm == "StatusMessage":
            msg = (child.text or "").strip()
    return overall, msg


# -----------------------------
# Secrets + Auth helpers
# -----------------------------
def _load_secret_json() -> dict:
    if not SFMC_SECRET_REF:
        raise ValueError("Missing required env var SFMC_SECRET_ARN or SFMC_SECRET_ID")
    resp = secrets.get_secret_value(SecretId=SFMC_SECRET_REF)
    secret_str = resp.get("SecretString") or "{}"
    try:
        return json.loads(secret_str)
    except Exception:
        raise ValueError("SecretString is not valid JSON")


def _derive_rest_from_auth(auth_base: str) -> str:
    # legacy convenience; host swap is handled more safely via _swap_host_segment
    return _norm_base(auth_base.replace(".auth.", ".rest."))


def _derive_soap_from_auth(auth_base: str) -> str:
    # legacy convenience; host swap is handled more safely via _swap_host_segment
    return _norm_base(auth_base.replace(".auth.", ".soap."))


def _ensure_service_asmx(url: str) -> str:
    u = _norm_base(url)
    if not u:
        return u
    # Keep existing case if already present
    return u if u.lower().endswith("/service.asmx") else (u + "/Service.asmx")


def _get_sfmc_bases(secret: dict) -> Tuple[str, str, str]:
    """
    Returns (auth_base, rest_base, soap_base).

    Notes:
    - auth_base may be provided as a full token URL in some secrets; we normalize to base host URL.
    - rest/soap are derived from auth_base host if not explicitly provided.
    """
    auth_candidate = (
        SFMC_AUTH_BASE_URL
        or secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
        or secret.get("authUrl", "")
        or secret.get("auth_url_base", "")
    )
    auth_base = _strip_known_auth_paths(auth_candidate)
    if not auth_base:
        raise ValueError("Missing auth base URL (set SFMC_AUTH_BASE_URL or secret.auth_url/auth_base_url)")

    # Prefer explicit rest/soap bases if provided (and normalize to host-only base)
    rest_candidate = SFMC_REST_BASE_URL or secret.get("rest_base_url", "") or secret.get("rest_url", "") or ""
    soap_candidate = SFMC_SOAP_BASE_URL or secret.get("soap_base_url", "") or secret.get("soap_url", "") or ""

    rest_base = _url_base_only(rest_candidate) if rest_candidate else ""
    soap_base = _url_base_only(soap_candidate) if soap_candidate else ""

    if not rest_base:
        # safer host swap than raw replace on whole string
        rest_base = _swap_host_segment(auth_base, ".auth.", ".rest.") or _derive_rest_from_auth(auth_base)

    if not soap_base:
        soap_base = _swap_host_segment(auth_base, ".auth.", ".soap.") or _derive_soap_from_auth(auth_base)

    soap_base = _ensure_service_asmx(_norm_base(soap_base))

    return _norm_base(auth_base), _norm_base(rest_base), soap_base


def _secret_account_id(secret: dict) -> Optional[str]:
    acct = secret.get("account_id") or secret.get("accountId")
    acct = str(acct).strip() if acct is not None else ""
    return acct or None


def _enforce_account_guardrail(secret: dict) -> None:
    if not SFMC_ALLOWED_ACCOUNT_ID:
        return
    acct = _secret_account_id(secret)
    if not acct:
        raise ValueError("Guardrail: SFMC_ALLOWED_ACCOUNT_ID is set but secret has no account_id/accountId")
    if acct != SFMC_ALLOWED_ACCOUNT_ID:
        raise ValueError(f"Guardrail: account_id {acct} not allowed (expected {SFMC_ALLOWED_ACCOUNT_ID})")


def _get_access_token(force_refresh: bool = False) -> Tuple[str, str, str, str, dict]:
    """
    Returns:
      (access_token, rest_base, soap_base, auth_base, meta)

    force_refresh=True clears the warm token cache to force a real token fetch.
    """
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
        return (
            _TOKEN_CACHE["access_token"],
            _TOKEN_CACHE["rest_base_url"],
            _TOKEN_CACHE["soap_base_url"],
            _TOKEN_CACHE["auth_base_url"],
            meta,
        )

    secret = _load_secret_json()
    _enforce_account_guardrail(secret)

    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    account_id = secret.get("account_id") or secret.get("accountId")

    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id and client_secret")

    auth_base, rest_base, soap_base = _get_sfmc_bases(secret)

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
    token_soap = body.get("soap_instance_url") or body.get("soapInstanceUrl")
    if token_rest:
        rest_base = _url_base_only(token_rest)
    if token_soap:
        soap_base = _ensure_service_asmx(_url_base_only(token_soap))

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base
    _TOKEN_CACHE["soap_base_url"] = soap_base
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
    return access_token, rest_base, soap_base, auth_base, meta


def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


def _host_from_url(url: str) -> Optional[str]:
    """
    Extracts host (without port) from a URL or host string.
    """
    try:
        u = (url or "").strip()
        if not u:
            return None
        u = _ensure_scheme(u)
        p = urlparse(u)
        netloc = p.netloc or ""
        if not netloc and p.path:
            netloc = p.path.split("/", 1)[0]
        host = netloc.split("@")[-1]  # strip any userinfo
        host = host.split(":", 1)[0]  # strip port
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


def _classify_http_failure(http_status: int, err_text: str) -> str:
    s = (err_text or "").lower()
    if http_status in (401,):
        return "auth_unauthorized"
    if http_status in (403,):
        return "auth_forbidden"
    if http_status in (404,):
        return "not_found_or_wrong_bu_or_wrong_base_url"
    if http_status >= 500 and http_status != 599:
        return "server_error"
    if http_status == 599:
        if "timed out" in s or "timeout" in s:
            return "timeout_or_network"
        return "network_error"
    return "unexpected_http_status"


# -----------------------------
# Health checks
# -----------------------------
def _check_runtime_config() -> dict:
    missing = []
    if not SFMC_SECRET_REF:
        missing.append("SFMC_SECRET_ARN|SFMC_SECRET_ID")
    if not SFMC_ENV:
        missing.append("SFMC_ENV")

    if SFMC_ENV != REQUIRED_SFMC_ENV:
        return {
            "status": "FAIL",
            "details": {
                "sfmcEnv": SFMC_ENV or None,
                "requiredSandbox": REQUIRED_SFMC_ENV,
                "missingEnv": missing,
            },
            "hints": [
                f"Sandbox guardrail blocked execution. Set SFMC_ENV={REQUIRED_SFMC_ENV}.",
                "If this is truly a sandbox tenant, confirm you are using sandbox credentials/BU and the sandbox OAuth app.",
            ],
        }

    if missing:
        return {
            "status": "FAIL",
            "details": {
                "sfmcEnv": SFMC_ENV,
                "requiredSandbox": REQUIRED_SFMC_ENV,
                "missingEnv": missing,
            },
            "hints": [
                "Missing required runtime configuration. Add the missing env vars and retry.",
            ],
        }

    return {
        "status": "PASS",
        "details": {
            "sfmcEnv": SFMC_ENV,
            "requiredSandbox": REQUIRED_SFMC_ENV,
            "missingEnv": [],
            "hostSuffixGuardrailEnforced": bool(SFMC_ALLOWED_HOST_SUFFIXES),
            "hostSuffixAllowlist": SFMC_ALLOWED_HOST_SUFFIXES,
        },
        "hints": [],
    }


def _check_secrets_access() -> Tuple[dict, Optional[dict]]:
    try:
        secret = _load_secret_json()
        acct = _secret_account_id(secret)
        return (
            {"status": "PASS", "details": {"readSecret": True, "secretHasAccountId": bool(acct)}, "hints": []},
            secret,
        )
    except Exception as e:
        return (
            {
                "status": "FAIL",
                "details": {"readSecret": False, "error": str(e)},
                "hints": [
                    "Check SFMC_SECRET_ID/SFMC_SECRET_ARN points to an existing secret.",
                    "Ensure Lambda role has secretsmanager:GetSecretValue and kms:Decrypt (if secret is encrypted).",
                ],
            },
            None,
        )


def _check_account_guardrail(secret: Optional[dict]) -> Tuple[dict, dict]:
    evidence = {}

    if not SFMC_ALLOWED_ACCOUNT_ID:
        return (
            {
                "status": "SKIP",
                "details": {"enforced": False},
                "hints": ["SFMC_ALLOWED_ACCOUNT_ID not set (recommended to set for sandbox safety)."],
            },
            evidence,
        )

    if not secret:
        return (
            {
                "status": "SKIP",
                "details": {"enforced": True},
                "hints": ["Blocked: could not load secret to validate account guardrail (secretsAccess failed)."],
            },
            evidence,
        )

    actual = _secret_account_id(secret)
    evidence["accountId"] = actual

    if not actual:
        return (
            {
                "status": "FAIL",
                "details": {"enforced": True, "expectedAccountId": SFMC_ALLOWED_ACCOUNT_ID, "actualAccountId": None},
                "hints": [
                    "SFMC_ALLOWED_ACCOUNT_ID is set, but secret does not include account_id/accountId.",
                    "Add account_id to the secret (recommended) or remove SFMC_ALLOWED_ACCOUNT_ID (not recommended).",
                ],
            },
            evidence,
        )

    if actual != SFMC_ALLOWED_ACCOUNT_ID:
        return (
            {
                "status": "FAIL",
                "details": {"enforced": True, "expectedAccountId": SFMC_ALLOWED_ACCOUNT_ID, "actualAccountId": actual},
                "hints": [
                    "Account guardrail mismatch. This usually means wrong BU/account scope or wrong secret.",
                    "Fix by updating SFMC_ALLOWED_ACCOUNT_ID or pointing SFMC_SECRET_ID to the correct sandbox OAuth app credentials.",
                ],
            },
            evidence,
        )

    return (
        {
            "status": "PASS",
            "details": {"enforced": True, "expectedAccountId": SFMC_ALLOWED_ACCOUNT_ID, "actualAccountId": actual},
            "hints": [],
        },
        evidence,
    )


def _check_sfmc_auth(force_refresh: bool = False) -> Tuple[dict, dict]:
    try:
        access_token, rest_base, soap_base, auth_base, meta = _get_access_token(force_refresh=force_refresh)
        _ = access_token  # do not log/return token

        auth_host = _host_from_url(auth_base)
        rest_host = _host_from_url(rest_base)
        soap_host = _host_from_url(soap_base)

        evidence = {
            "authHost": auth_host,
            "restHost": rest_host,
            "soapHost": soap_host,
            "accountId": meta.get("accountId"),
        }

        details = dict(evidence)
        details.update({
            "tokenCacheHit": bool(meta.get("tokenCacheHit")),
            "tokenExpiresInSecRemaining": int(meta.get("tokenExpiresInSecRemaining") or 0),
            "forcedRefreshRequested": bool(meta.get("forcedRefreshRequested")),
            "forcedRefreshPerformed": bool(meta.get("forcedRefreshPerformed")),
            "hostSuffixGuardrailEnforced": bool(SFMC_ALLOWED_HOST_SUFFIXES),
            "hostSuffixGuardrailPassed": (
                _host_allowed(auth_host) and _host_allowed(rest_host) and _host_allowed(soap_host)
            ) if SFMC_ALLOWED_HOST_SUFFIXES else None,
        })

        if SFMC_ALLOWED_HOST_SUFFIXES:
            bad = []
            if not _host_allowed(auth_host):
                bad.append({"which": "authHost", "value": auth_host})
            if not _host_allowed(rest_host):
                bad.append({"which": "restHost", "value": rest_host})
            if not _host_allowed(soap_host):
                bad.append({"which": "soapHost", "value": soap_host})
            if bad:
                return (
                    {
                        "status": "FAIL",
                        "details": {
                            "error": "HostSuffixGuardrailFailed",
                            "badHosts": bad,
                            "allowlist": SFMC_ALLOWED_HOST_SUFFIXES
                        },
                        "hints": [
                            "Host suffix guardrail failed. This can indicate wrong instance URLs or non-SFMC endpoints.",
                            "Either fix SFMC base URLs/credentials, or update SFMC_ALLOWED_HOST_SUFFIXES (recommended to keep strict).",
                        ],
                    },
                    evidence,
                )

        return (
            {"status": "PASS", "details": details, "hints": []},
            evidence,
        )
    except Exception as e:
        msg = str(e)
        return (
            {
                "status": "FAIL",
                "details": {"error": msg, "forcedRefreshRequested": bool(force_refresh)},
                "hints": [
                    "Verify OAuth app client_id/client_secret and (if set) account_id.",
                    "If SFMC_ALLOWED_ACCOUNT_ID is set, ensure secret account_id matches.",
                    "If this began failing recently, run Health Inspector in configOnly and confirm env/secret wiring, then retry.",
                ],
            },
            {},
        )


def _probe_rest_endpoint(access_token: str, rest_base: str, path: str) -> dict:
    headers = _sfmc_headers(access_token)
    url = f"{_norm_base(rest_base)}{path}"

    t0 = _perf_ms()
    status, body = _http_json("GET", url, headers=headers, payload=None, timeout=REST_TIMEOUT)
    duration = int(_perf_ms() - t0)

    if 200 <= status < 300:
        return {"status": "PASS", "durationMs": duration, "details": {"httpStatus": status}, "hints": []}

    err_txt = ""
    if isinstance(body, dict):
        err_txt = body.get("error") or body.get("message") or json.dumps(body)[:500]
    else:
        err_txt = str(body)[:500]

    classification = _classify_http_failure(status, err_txt)
    return {
        "status": "FAIL",
        "durationMs": duration,
        "details": {"httpStatus": status, "errorClass": classification, "error": err_txt},
        "hints": [
            "If 401/403: likely OAuth permissions or wrong client credentials/BU scope.",
            "If 404: often wrong base URL, wrong BU/account scope, or endpoint not available in this stack.",
            "If 599: network/DNS/timeout — check VPC/NAT, outbound internet, or SFMC availability.",
        ],
    }


def _probe_soap_data_extension(access_token: str, soap_base: str) -> dict:
    filter_xml = _soap_simple_filter("Name", "equals", "__sfmc_health_probe__")
    body_xml = _soap_retrieve_request_xml(
        object_type="DataExtension",
        properties=["Name", "CustomerKey"],
        filter_xml=filter_xml
    )
    env = _soap_envelope(access_token, body_xml)

    t0 = _perf_ms()
    status, resp_xml = _http_soap(_ensure_service_asmx(soap_base), env, timeout=SOAP_TIMEOUT)
    duration = int(_perf_ms() - t0)

    if 200 <= status < 300:
        overall, status_msg = _soap_overall_status(resp_xml)
        if overall:
            o = overall.strip().lower()
            if o not in ("ok", "moredataavailable"):
                return {
                    "status": "FAIL",
                    "durationMs": duration,
                    "details": {"httpStatus": status, "soapOverallStatus": overall, "soapStatusMessage": status_msg},
                    "hints": [
                        "SOAP responded but OverallStatus is not OK. This may indicate permission issues for the DataExtension object.",
                    ],
                }
        return {
            "status": "PASS",
            "durationMs": duration,
            "details": {"httpStatus": status, "soapOverallStatus": overall},
            "hints": []
        }

    fault = _soap_fault_summary(resp_xml)
    classification = _classify_http_failure(status, fault or resp_xml[:300])
    return {
        "status": "FAIL",
        "durationMs": duration,
        "details": {"httpStatus": status, "errorClass": classification, "soapFault": fault or None},
        "hints": [
            "If auth-related: verify token and SOAP instance URL.",
            "If 599 timeout/network: check outbound connectivity and SFMC SOAP availability.",
        ],
    }


def _compute_overall_status(checks: list) -> str:
    statuses = [c.get("status") for c in checks]
    if "FAIL" in statuses:
        return "FAIL"
    if "WARN" in statuses:
        return "WARN"
    return "PASS"


def _checks_summary(checks: list) -> dict:
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    failed = []
    skipped = []
    warned = []
    for c in checks or []:
        st = c.get("status") or "SKIP"
        if st not in counts:
            counts[st] = 0
        counts[st] += 1
        if st == "FAIL":
            failed.append(c.get("name"))
        if st == "SKIP":
            skipped.append(c.get("name"))
        if st == "WARN":
            warned.append(c.get("name"))
    return {
        "counts": counts,
        "failedChecks": [x for x in failed if x],
        "warnChecks": [x for x in warned if x],
        "skippedChecks": [x for x in skipped if x],
    }


def _normalize_mode_strict(mode_raw: Any) -> Optional[str]:
    """
    Returns:
      - "quick"|"configonly"|"coldstart" when valid (including alias spellings)
      - None when caller provided an invalid non-empty value
    """
    s = "" if mode_raw is None else str(mode_raw).strip()
    if not s:
        return "quick"

    m = s.lower()
    m = m.replace("_", "").replace("-", "").replace(" ", "")

    if m in ("quick",):
        return "quick"
    if m in ("configonly", "config"):
        return "configonly"
    if m in ("coldstart", "cold"):
        return "coldstart"
    return None


def _bad_request(message: str) -> Tuple[int, dict]:
    return 400, {
        "ok": False,
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "error": "BadRequest",
        "message": message,
    }


# -----------------------------
# Main health report
# -----------------------------
def build_health_report(params: dict) -> Tuple[int, dict]:
    requested_inputs_raw = dict(params or {})
    requested_inputs = _sanitize_requested_inputs(requested_inputs_raw)

    # --- Validate mode (DO NOT silently coerce unknown values) ---
    mode_norm = _normalize_mode_strict(requested_inputs_raw.get("mode"))
    if mode_norm is None:
        return _bad_request(
            f"Invalid mode '{requested_inputs_raw.get('mode')}'. Allowed: quick, configOnly, coldstart."
        )
    mode = mode_norm

    # --- Validate booleans strictly if supplied ---
    k_rest, v_rest = _first_present(requested_inputs_raw, ["includeRestProbes", "includeRestProbe", "includeRest"])
    if k_rest is None:
        include_rest = True
    else:
        include_rest, ok = _to_bool_strict(v_rest, default=True)
        if not ok:
            return _bad_request(f"Invalid boolean for '{k_rest}': '{v_rest}'. Use true/false.")

    k_soap, v_soap = _first_present(requested_inputs_raw, ["includeSoapProbe", "includeSoap"])
    if k_soap is None:
        include_soap = True
    else:
        include_soap, ok = _to_bool_strict(v_soap, default=True)
        if not ok:
            return _bad_request(f"Invalid boolean for '{k_soap}': '{v_soap}'. Use true/false.")

    force_refresh = False
    for k in ["forceTokenRefresh", "forceAuthRefresh", "simulateColdStart"]:
        if k in requested_inputs_raw:
            bval, ok = _to_bool_strict(requested_inputs_raw.get(k), default=False)
            if not ok:
                return _bad_request(f"Invalid boolean for '{k}': '{requested_inputs_raw.get(k)}'. Use true/false.")
            force_refresh = force_refresh or bool(bval)

    # mode=coldstart implies token refresh
    if mode == "coldstart":
        force_refresh = True

    # In configOnly: explicitly do NOT auth/probe, and do NOT refresh tokens
    if mode == "configonly":
        include_rest = False
        include_soap = False
        force_refresh = False

    effective_inputs = {
        "mode": mode,
        "includeRestProbes": bool(include_rest),
        "includeSoapProbe": bool(include_soap),
        "forceTokenRefresh": bool(force_refresh),
    }

    t_start = _perf_ms()
    checks: List[dict] = []
    warnings: List[str] = []
    skipped_checks: List[dict] = []

    def _add_skip(name: str, reason: str):
        checks.append({"name": name, "status": "SKIP", "details": {"reason": reason}, "hints": [reason]})
        skipped_checks.append({"name": name, "reason": reason})

    # 1) runtimeConfig (always first, and hard stop if FAIL)
    t0 = _perf_ms()
    rc = _check_runtime_config()
    checks.append({
        "name": "runtimeConfig",
        "status": rc["status"],
        "durationMs": int(_perf_ms() - t0),
        "details": rc.get("details", {}),
        "hints": rc.get("hints", []),
    })

    sandbox_signals = []
    if SFMC_ENV:
        sandbox_signals.append({"signal": "env.SFMC_ENV", "value": SFMC_ENV, "confidence": "high"})
    if SFMC_ALLOWED_ACCOUNT_ID:
        sandbox_signals.append({"signal": "SFMC_ALLOWED_ACCOUNT_ID_enforced", "value": SFMC_ALLOWED_ACCOUNT_ID, "confidence": "medium"})
    if SFMC_ALLOWED_HOST_SUFFIXES:
        sandbox_signals.append({"signal": "SFMC_ALLOWED_HOST_SUFFIXES_enforced", "value": ",".join(SFMC_ALLOWED_HOST_SUFFIXES), "confidence": "medium"})

    # If runtimeConfig fails, skip everything else
    if rc["status"] != "PASS":
        reason = "Blocked by runtimeConfig failure (sandbox guardrail or missing env)."
        for nm in ["secretsAccess", "accountGuardrail", "sfmcAuth", "restProbeAutomation", "restProbeJourney", "soapProbeDataExtension"]:
            _add_skip(nm, reason)

        overall = _compute_overall_status(checks)
        summary = _checks_summary(checks)
        out = {
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "overallStatus": overall,
            "healthOk": (overall == "PASS"),
            "timestampUtc": _now_utc_iso(),
            "sfmcEnv": SFMC_ENV or None,
            "sandboxSignals": sandbox_signals,
            "evidence": {},
            "requestedInputs": requested_inputs,
            "effectiveInputs": effective_inputs,
            "skippedChecks": skipped_checks,
            "checksSummary": summary,
            "checks": checks,
            "timings": {"totalMs": int(_perf_ms() - t_start)},
        }
        if skipped_checks:
            warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")
        return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}

    # mode=configOnly: ONLY runtimeConfig; explicitly SKIP the rest (clarity + auditability)
    if mode == "configonly":
        reason = "mode=configOnly (no secrets/auth/SFMC calls)"
        for nm in ["secretsAccess", "accountGuardrail", "sfmcAuth", "restProbeAutomation", "restProbeJourney", "soapProbeDataExtension"]:
            _add_skip(nm, reason)

        overall = _compute_overall_status(checks)
        summary = _checks_summary(checks)
        out = {
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "overallStatus": overall,
            "healthOk": (overall == "PASS"),
            "timestampUtc": _now_utc_iso(),
            "sfmcEnv": SFMC_ENV or None,
            "sandboxSignals": sandbox_signals,
            "evidence": {},
            "requestedInputs": requested_inputs,
            "effectiveInputs": effective_inputs,
            "skippedChecks": skipped_checks,
            "checksSummary": summary,
            "checks": checks,
            "timings": {"totalMs": int(_perf_ms() - t_start)},
        }
        warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")
        return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}

    # 2) secretsAccess
    t0 = _perf_ms()
    sa, secret = _check_secrets_access()
    checks.append({
        "name": "secretsAccess",
        "status": sa["status"],
        "durationMs": int(_perf_ms() - t0),
        "details": sa.get("details", {}),
        "hints": sa.get("hints", []),
    })

    if sa["status"] != "PASS":
        reason = "Blocked because secretsAccess failed (cannot load credentials)."
        for nm in ["accountGuardrail", "sfmcAuth", "restProbeAutomation", "restProbeJourney", "soapProbeDataExtension"]:
            _add_skip(nm, reason)

        overall = _compute_overall_status(checks)
        summary = _checks_summary(checks)
        out = {
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "overallStatus": overall,
            "healthOk": (overall == "PASS"),
            "timestampUtc": _now_utc_iso(),
            "sfmcEnv": SFMC_ENV or None,
            "sandboxSignals": sandbox_signals,
            "evidence": {},
            "requestedInputs": requested_inputs,
            "effectiveInputs": effective_inputs,
            "skippedChecks": skipped_checks,
            "checksSummary": summary,
            "checks": checks,
            "timings": {"totalMs": int(_perf_ms() - t_start)},
        }
        if skipped_checks:
            warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")
        return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}

    # 2b) accountGuardrail
    t0 = _perf_ms()
    ag, ag_evidence = _check_account_guardrail(secret)
    checks.append({
        "name": "accountGuardrail",
        "status": ag["status"],
        "durationMs": int(_perf_ms() - t0),
        "details": ag.get("details", {}),
        "hints": ag.get("hints", []),
    })

    evidence: Dict[str, Any] = {}
    if ag_evidence:
        evidence.update(ag_evidence)

    if ag["status"] == "FAIL":
        reason = "Blocked because accountGuardrail failed (wrong BU/account scope or wrong secret)."
        for nm in ["sfmcAuth", "restProbeAutomation", "restProbeJourney", "soapProbeDataExtension"]:
            _add_skip(nm, reason)

        overall = _compute_overall_status(checks)
        summary = _checks_summary(checks)
        out = {
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "overallStatus": overall,
            "healthOk": (overall == "PASS"),
            "timestampUtc": _now_utc_iso(),
            "sfmcEnv": SFMC_ENV or None,
            "sandboxSignals": sandbox_signals,
            "evidence": evidence,
            "requestedInputs": requested_inputs,
            "effectiveInputs": effective_inputs,
            "skippedChecks": skipped_checks,
            "checksSummary": summary,
            "checks": checks,
            "timings": {"totalMs": int(_perf_ms() - t_start)},
        }
        if skipped_checks:
            warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")
        return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}

    # 3) sfmcAuth
    t0 = _perf_ms()
    auth_check, auth_evidence = _check_sfmc_auth(force_refresh=force_refresh)
    checks.append({
        "name": "sfmcAuth",
        "status": auth_check["status"],
        "durationMs": int(_perf_ms() - t0),
        "details": auth_check.get("details", {}),
        "hints": auth_check.get("hints", []),
    })

    if auth_evidence:
        evidence.update(auth_evidence)

    if auth_check["status"] != "PASS":
        reason = "Blocked because sfmcAuth failed (cannot obtain token / resolve instance URLs / host guardrail)."
        for nm in ["restProbeAutomation", "restProbeJourney", "soapProbeDataExtension"]:
            _add_skip(nm, reason)

        overall = _compute_overall_status(checks)
        summary = _checks_summary(checks)
        out = {
            "tool": TOOL_NAME,
            "toolVersion": TOOL_VERSION,
            "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
            "overallStatus": overall,
            "healthOk": (overall == "PASS"),
            "timestampUtc": _now_utc_iso(),
            "sfmcEnv": SFMC_ENV or None,
            "sandboxSignals": sandbox_signals,
            "evidence": evidence,
            "requestedInputs": requested_inputs,
            "effectiveInputs": effective_inputs,
            "skippedChecks": skipped_checks,
            "checksSummary": summary,
            "checks": checks,
            "timings": {"totalMs": int(_perf_ms() - t_start)},
        }
        if skipped_checks:
            warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")
        return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}

    # Reuse token & bases for probes
    access_token, rest_base, soap_base, _auth_base, _meta = _get_access_token(force_refresh=False)
    _ = _auth_base
    _ = _meta

    # 4) probes (REST)
    if include_rest:
        ra = _probe_rest_endpoint(access_token, rest_base, "/automation/v1/automations?$pageSize=1")
        checks.append({
            "name": "restProbeAutomation",
            "status": ra["status"],
            "durationMs": ra.get("durationMs", 0),
            "details": ra.get("details", {}),
            "hints": ra.get("hints", []),
        })

        rj = _probe_rest_endpoint(access_token, rest_base, "/interaction/v1/interactions?$pageSize=1")
        checks.append({
            "name": "restProbeJourney",
            "status": rj["status"],
            "durationMs": rj.get("durationMs", 0),
            "details": rj.get("details", {}),
            "hints": rj.get("hints", []),
        })
    else:
        _add_skip("restProbeAutomation", "includeRestProbes=false")
        _add_skip("restProbeJourney", "includeRestProbes=false")

    # 5) probe (SOAP)
    if include_soap:
        sd = _probe_soap_data_extension(access_token, soap_base)
        checks.append({
            "name": "soapProbeDataExtension",
            "status": sd["status"],
            "durationMs": sd.get("durationMs", 0),
            "details": sd.get("details", {}),
            "hints": sd.get("hints", []),
        })
    else:
        _add_skip("soapProbeDataExtension", "includeSoapProbe=false")

    if skipped_checks:
        warnings.append(f"Some checks were skipped: {', '.join([s['name'] for s in skipped_checks])}")

    overall = _compute_overall_status(checks)
    summary = _checks_summary(checks)

    out = {
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "overallStatus": overall,
        "healthOk": (overall == "PASS"),
        "timestampUtc": _now_utc_iso(),
        "sfmcEnv": SFMC_ENV or None,
        "sandboxSignals": sandbox_signals,
        "evidence": evidence,
        "requestedInputs": requested_inputs,
        "effectiveInputs": effective_inputs,
        "skippedChecks": skipped_checks,
        "checksSummary": summary,
        "checks": checks,
        "timings": {"totalMs": int(_perf_ms() - t_start)},
    }
    return 200, {"ok": True, "tool": TOOL_NAME, "input": requested_inputs, "output": out, "warnings": warnings}


# -----------------------------
# Handlers
# -----------------------------
def handle_healthz() -> Tuple[int, dict]:
    missing = []
    if not SFMC_ENV:
        missing.append("SFMC_ENV")
    if not SFMC_SECRET_REF:
        missing.append("SFMC_SECRET_ARN|SFMC_SECRET_ID")

    sandbox_guardrail_ok = bool(SFMC_ENV) and (SFMC_ENV == REQUIRED_SFMC_ENV)

    return 200, {
        "ok": True,
        "tool": TOOL_NAME,
        "toolVersion": TOOL_VERSION,
        "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
        "sfmcEnv": SFMC_ENV or None,
        "requiredEnvPresent": len(missing) == 0,
        "missingEnv": missing,
        "sandboxGuardrailOk": sandbox_guardrail_ok,
        "requiredSandboxValue": REQUIRED_SFMC_ENV,
        "hostSuffixGuardrailEnforced": bool(SFMC_ALLOWED_HOST_SUFFIXES),
        "hostSuffixAllowlist": SFMC_ALLOWED_HOST_SUFFIXES,
    }


def lambda_handler(event, context):
    api_path = _get_api_path(event).lower()
    method = _get_http_method(event).upper()

    # Helpful default for direct-invoke tests where no route is provided
    if not api_path:
        api_path = "/healthreport"

    bedrock = bool(isinstance(event, dict) and _is_bedrock_event(event))

    try:
        # Avoid logging entire event (can be huge / may contain sensitive structures)
        logger.info("Incoming event keys: %s", list(event.keys()) if isinstance(event, dict) else type(event))
        logger.info("Resolved route: %s %s", method, api_path)
    except Exception:
        pass

    def _is_report_path(p: str) -> bool:
        return p in ("/healthreport", "/health", "/report")

    try:
        # --- Route/method validation (keeps Lambda behavior aligned with OpenAPI) ---
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
                "supported": _supported_routes_payload(),
                "allowedMethods": allowed or None,
            }
            if bedrock:
                return _bedrock_actiongroup_response(event, payload, http_code=status_code)
            return _json_response(payload, status_code)

        # Bedrock-style
        if bedrock:
            if api_path == "/healthz" and method == "GET":
                status, body = handle_healthz()
                return _bedrock_actiongroup_response(event, body, http_code=status)

            if _is_report_path(api_path) and method in ("POST", "GET"):
                params = _parse_json_body(event) or {}
                if method == "GET":
                    qp = _parse_query_params(event)
                    merged = dict(params)
                    merged.update(qp)  # query overrides
                    params = merged
                status, body = build_health_report(params)
                return _bedrock_actiongroup_response(event, body, http_code=status)

            # Defensive fallback (should be unreachable due to route validation)
            return _bedrock_actiongroup_response(
                event,
                {
                    "ok": False,
                    "tool": TOOL_NAME,
                    "toolVersion": TOOL_VERSION,
                    "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
                    "error": "BadRequest",
                    "message": f"Unsupported route: {method} {api_path}",
                    "supported": _supported_routes_payload(),
                },
                http_code=400
            )

        # Direct invoke / API GW-style
        if api_path == "/healthz" and method == "GET":
            status, body = handle_healthz()
            return _json_response(body, status)

        if _is_report_path(api_path) and method in ("POST", "GET"):
            params = _parse_json_body(event) or {}
            if method == "GET":
                qp = _parse_query_params(event)
                params = dict(params)
                params.update(qp)  # query overrides
            status, body = build_health_report(params)
            return _json_response(body, status)

        # Defensive fallback (should be unreachable due to route validation)
        return _json_response(
            {
                "ok": False,
                "tool": TOOL_NAME,
                "toolVersion": TOOL_VERSION,
                "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
                "error": "BadRequest",
                "message": f"Unsupported route: {method} {api_path}",
                "supported": _supported_routes_payload(),
            },
            400
        )

    except Exception as e:
        err = str(e)
        logger.exception("Unhandled error")
        if bedrock:
            return _bedrock_actiongroup_response(
                event,
                {
                    "ok": False,
                    "tool": TOOL_NAME,
                    "toolVersion": TOOL_VERSION,
                    "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
                    "error": "UnhandledError",
                    "message": err
                },
                http_code=500
            )
        return _json_response(
            {
                "ok": False,
                "tool": TOOL_NAME,
                "toolVersion": TOOL_VERSION,
                "outputSchemaVersion": OUTPUT_SCHEMA_VERSION,
                "error": "UnhandledError",
                "message": err
            },
            500
        )
