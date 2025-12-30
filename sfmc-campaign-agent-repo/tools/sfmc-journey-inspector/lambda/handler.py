import os
import json
import time
import logging
import re
from typing import Any, Dict, Optional, Tuple, List, Set
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Guardrails / hard caps
# -----------------------------
SFMC_ENV = (os.getenv("SFMC_ENV") or "sandbox").strip().lower()
SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "30"))

# SFMC interactions endpoint max page size is typically 50; keep this tight.
JOURNEY_MAX_PAGE_SIZE = int(os.getenv("JOURNEY_MAX_PAGE_SIZE", "50"))
MAX_PAGE_SIZE = min(max(JOURNEY_MAX_PAGE_SIZE, 1), 50)

JOURNEY_ALLOW_EXTRAS_ALL = str(os.getenv("JOURNEY_ALLOW_EXTRAS_ALL", "false")).lower() == "true"
JOURNEY_DEFAULT_EXTRAS = (os.getenv("JOURNEY_DEFAULT_EXTRAS") or "").strip()

# Allowlist extras (comma-separated); typical values: activities,stats,outcome,all
JOURNEY_EXTRAS_ALLOWED = set(
    [x.strip().lower() for x in (os.getenv("JOURNEY_EXTRAS_ALLOWED") or "activities,stats,outcome").split(",") if x.strip()]
)

DEBUG_REST = str(os.getenv("DEBUG_REST", "false")).lower() == "true"
DEBUG_REST_TRUNCATE = int(os.getenv("DEBUG_REST_TRUNCATE", "1200"))

# Bedrock often treats non-2xx from action-group as "tool failed" (424).
# Default: force action-group httpStatusCode=200 and embed real status in JSON.
BEDROCK_FORCE_200 = str(os.getenv("BEDROCK_FORCE_200", "true")).lower() == "true"

# Cap summaries to keep Bedrock payload safe
ACTIVITY_SUMMARY_MAX_ITEMS = int(os.getenv("ACTIVITY_SUMMARY_MAX_ITEMS", "150"))

# Topology caps (Bedrock payload safety)
TOPOLOGY_MAX_NODES = int(os.getenv("TOPOLOGY_MAX_NODES", "250"))
TOPOLOGY_MAX_EDGES = int(os.getenv("TOPOLOGY_MAX_EDGES", "800"))

# Lightweight reference extraction caps (avoid huge recursion / payloads)
REF_SCAN_MAX_ITEMS = int(os.getenv("REF_SCAN_MAX_ITEMS", "1200"))
REF_SCAN_MAX_DEPTH = int(os.getenv("REF_SCAN_MAX_DEPTH", "8"))

# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
}

# -----------------------------
# Helpers: JSON / HTTP
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

def _http_json(
    method: str,
    url: str,
    headers: dict,
    payload: Optional[dict] = None,
    timeout: int = REST_TIMEOUT
) -> Tuple[int, dict]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers = dict(headers or {})
        headers["Content-Type"] = "application/json"

    req = Request(url=url, data=data, headers=headers or {}, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if DEBUG_REST:
                logger.info("REST %s %s -> %s\n%s", method.upper(), url, resp.status, raw[:DEBUG_REST_TRUNCATE])
            if not raw:
                return resp.status, {}
            return resp.status, json.loads(raw)
    except HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        if DEBUG_REST:
            logger.info("REST ERROR %s %s -> %s\n%s", method.upper(), url, e.code, raw[:DEBUG_REST_TRUNCATE])
        try:
            return e.code, json.loads(raw) if raw else {"error": raw}
        except Exception:
            return e.code, {"error": raw or str(e)}
    except URLError as e:
        return 599, {"error": f"URLError: {e}"}

# -----------------------------
# Secrets + SFMC Auth
# -----------------------------
def _load_secret_json() -> dict:
    secret_ref = (os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or "").strip()
    if not secret_ref:
        raise ValueError("Missing required env var SFMC_SECRET_ARN or SFMC_SECRET_ID")
    resp = secrets.get_secret_value(SecretId=secret_ref)
    secret_str = resp.get("SecretString") or "{}"
    try:
        return json.loads(secret_str)
    except Exception:
        raise ValueError("SecretString is not valid JSON")

def _enforce_account_guardrail(secret: dict) -> None:
    if not SFMC_ALLOWED_ACCOUNT_ID:
        return
    acct = str(secret.get("account_id") or secret.get("accountId") or "").strip()
    if not acct:
        raise ValueError("Guardrail: SFMC_ALLOWED_ACCOUNT_ID is set but secret has no account_id/accountId")
    if acct != SFMC_ALLOWED_ACCOUNT_ID:
        raise ValueError(f"Guardrail: account_id {acct} not allowed (expected {SFMC_ALLOWED_ACCOUNT_ID})")

def _get_sfmc_auth_base(secret: dict) -> str:
    auth_base = _norm_base(
        os.getenv("SFMC_AUTH_BASE_URL", "")
        or secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
        or os.getenv("auth_url", "")
    )
    if not auth_base:
        raise ValueError("Missing auth base URL (set secret.auth_url or SFMC_AUTH_BASE_URL)")
    return auth_base

def _get_access_token() -> Tuple[str, str]:
    now = int(time.time())
    if _TOKEN_CACHE["access_token"] and now < int(_TOKEN_CACHE["expires_at"] or 0) - 30:
        return _TOKEN_CACHE["access_token"], _TOKEN_CACHE["rest_base_url"]

    if SFMC_ENV != "sandbox":
        raise ValueError(f"Guardrail: SFMC_ENV must be 'sandbox' (got '{SFMC_ENV}')")

    secret = _load_secret_json()
    _enforce_account_guardrail(secret)

    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    account_id = secret.get("account_id") or secret.get("accountId")

    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id and client_secret")

    auth_base = _get_sfmc_auth_base(secret)
    token_url = f"{auth_base}/v2/token"

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if account_id:
        payload["account_id"] = account_id

    status, body = _http_json("POST", token_url, headers={}, payload=payload)
    if status < 200 or status >= 300:
        raise RuntimeError(f"SFMC auth failed ({status}): {body}")

    access_token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 1200)

    if not access_token:
        raise RuntimeError(f"SFMC auth missing access_token: {body}")

    rest_base = body.get("rest_instance_url") or body.get("restInstanceUrl")
    if rest_base:
        rest_base = _norm_base(rest_base)
    else:
        rest_base = _norm_base(auth_base.replace(".auth.", ".rest."))

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base

    return access_token, rest_base

def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}

# -----------------------------
# Bedrock event extraction
# -----------------------------
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
    return _normalize_api_path(event.get("rawPath") or event.get("path") or "")

def _get_http_method(event: dict) -> str:
    m = event.get("httpMethod")
    if m:
        return str(m).upper()
    agi = event.get("actionGroupInvocationInput", {}) or {}
    v = agi.get("verb")
    if v:
        return str(v).upper()
    return "POST"

def _is_bedrock_event(event: dict) -> bool:
    return "messageVersion" in event and "response" not in event

def _bedrock_actiongroup_response(event: dict, body_obj: dict, http_code: int = 200) -> dict:
    action_group = (
        event.get("actionGroup")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("actionGroupName")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("actionGroup")
        or ""
    )
    api_path = _get_api_path(event)
    http_method = _get_http_method(event)
    eff_http = 200 if BEDROCK_FORCE_200 else int(http_code)

    return {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": action_group,
            "apiPath": api_path,
            "httpMethod": http_method,
            "httpStatusCode": eff_http,
            "responseBody": {
                "application/json": {"body": json.dumps(body_obj)}
            },
        },
        "sessionAttributes": event.get("sessionAttributes", {}) or {},
        "promptSessionAttributes": event.get("promptSessionAttributes", {}) or {},
    }

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
        if val is None:
            return []
        s = str(val).strip()
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
        return [x.strip() for x in s.split(",") if x.strip()]
    return val

def _parse_bedrock_params(event: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    plist = (
        event.get("parameters")
        or (event.get("actionGroupInvocationInput", {}) or {}).get("parameters")
        or []
    )
    if isinstance(plist, list):
        for p in plist:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(p.get("type"), p.get("value"))

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

    aj = content.get("application/json") or content.get("application_json")

    # Bedrock list-of-params format
    if isinstance(aj, list):
        for it in aj:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
        return out

    if isinstance(aj, dict):
        props = aj.get("properties")
        if isinstance(props, list):
            for it in props:
                if not isinstance(it, dict):
                    continue
                name = it.get("name")
                if not name:
                    continue
                out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            return out

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

def _clamp_page(page: Any) -> int:
    try:
        p = int(page)
    except Exception:
        p = 1
    return 1 if p < 1 else p

def _clamp_page_size(page_size: Any, cap: int = MAX_PAGE_SIZE, default: int = 25) -> Tuple[int, int]:
    try:
        req = int(page_size)
    except Exception:
        req = default
    eff = req
    if eff < 1:
        eff = 1
    if eff > cap:
        eff = cap
    return req, eff

def _sanitize_extras(extras: Optional[str], warnings: List[str]) -> str:
    x = (extras or JOURNEY_DEFAULT_EXTRAS or "").strip()
    if not x:
        return ""
    xl = x.lower().strip()
    if xl == "all" and not JOURNEY_ALLOW_EXTRAS_ALL:
        warnings.append("extras='all' is not allowed by backend guardrail; ignoring extras.")
        return ""
    if xl == "all" and JOURNEY_ALLOW_EXTRAS_ALL:
        return "all"
    parts = [p.strip().lower() for p in xl.split(",") if p.strip()]
    kept = []
    for p in parts:
        if p in JOURNEY_EXTRAS_ALLOWED:
            kept.append(p)
        else:
            warnings.append(f"extras value '{p}' is not allowlisted; ignoring it.")
    return ",".join(kept)

# -----------------------------
# Activities summary helpers
# -----------------------------
def _summarize_outcomes(outcomes: Any) -> List[dict]:
    if not isinstance(outcomes, list):
        return []
    out = []
    for o in outcomes:
        if not isinstance(o, dict):
            continue
        md = o.get("metaData") if isinstance(o.get("metaData"), dict) else {}
        out.append({
            "key": o.get("key"),
            "next": o.get("next"),
            "invalid": md.get("invalid") if isinstance(md, dict) else None,
        })
    return out

def _build_activities_summary(body: dict, max_items: int) -> dict:
    """
    Returns compact summaries designed to be Bedrock-safe.
    Only includes lightweight fields; caps list sizes to max_items.
    """
    activities_raw = body.get("activities")
    triggers_raw = body.get("triggers")

    activities_list: List[dict] = activities_raw if isinstance(activities_raw, list) else []
    triggers_list: List[dict] = triggers_raw if isinstance(triggers_raw, list) else []

    activities_total = len(activities_list)
    triggers_total = len(triggers_list)

    act_truncated = activities_total > max_items
    trg_truncated = triggers_total > max_items

    activities_list = activities_list[:max_items]
    triggers_list = triggers_list[:max_items]

    activities_summary = []
    for a in activities_list:
        if not isinstance(a, dict):
            continue
        activities_summary.append({
            "id": a.get("id"),
            "key": a.get("key"),
            "name": a.get("name"),
            "type": a.get("type"),
            "outcomes": _summarize_outcomes(a.get("outcomes")),
        })

    triggers_summary = []
    for t in triggers_list:
        if not isinstance(t, dict):
            continue
        triggers_summary.append({
            "id": t.get("id"),
            "key": t.get("key"),
            "name": t.get("name"),
            "type": t.get("type"),
        })

    return {
        "counts": {
            "activitiesTotal": activities_total,
            "triggersTotal": triggers_total,
        },
        "maxItems": max_items,
        "truncated": {
            "activities": act_truncated,
            "triggers": trg_truncated,
        },
        "activities": activities_summary,
        "triggers": triggers_summary,
    }

# -----------------------------
# SFMC Journey Builder calls
# -----------------------------
def _build_interactions_url(rest_base: str, path: str) -> str:
    rest_base = _norm_base(rest_base)
    return f"{rest_base}/interaction/v1{path}"

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def _looks_like_guid(s: str) -> bool:
    return bool(_GUID_RE.match((s or "").strip()))

def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None

def search_journeys(
    name_or_description: Optional[str],
    status: Optional[str],
    journey_id: Optional[str],
    key: Optional[str],
    most_recent_only: bool,
    extras: Optional[str],
    page: int,
    page_size: int,
    warn_on_404: bool = True,   # allow suppressing 404 warnings for internal probes
) -> dict:
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    warnings: List[str] = []
    extras_eff = _sanitize_extras(extras, warnings)

    page = _clamp_page(page)
    page_size_req, page_size_eff = _clamp_page_size(page_size, cap=MAX_PAGE_SIZE, default=25)

    qs = [f"$page={page}", f"$pageSize={page_size_eff}"]

    if name_or_description:
        qs.append(f"nameOrDescription={quote(str(name_or_description))}")
    if status:
        qs.append(f"status={quote(str(status))}")
    if journey_id:
        qs.append(f"id={quote(str(journey_id))}")
    if key:
        qs.append(f"key={quote(str(key))}")
    qs.append(f"mostRecentVersionOnly={'true' if bool(most_recent_only) else 'false'}")

    if extras_eff:
        qs.append(f"extras={quote(extras_eff)}")

    url = _build_interactions_url(rest_base, "/interactions") + "?" + "&".join(qs)
    status_code, body = _http_json("GET", url, headers=headers, payload=None)

    # treat 404 as "no results" (common SFMC behavior for key/id filters)
    if status_code == 404:
        if warn_on_404:
            warnings.append("No journeys found (SFMC returned 404).")
        body = body if isinstance(body, dict) else {"raw": body}
        return {
            "count": 0,
            "page": page,
            "pageSizeRequested": page_size_req,
            "pageSizeUsed": page_size_eff,
            "items": [],
            "raw": body if DEBUG_REST else {"note": "raw suppressed (enable DEBUG_REST=true to include)"},
            "warnings": warnings
        }

    if status_code < 200 or status_code >= 300:
        raise RuntimeError(f"searchJourneys failed ({status_code}): {body}")

    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        items = []

    def norm_item(it: dict) -> dict:
        if not isinstance(it, dict):
            return {}
        return {
            "id": it.get("id") or it.get("definitionId") or it.get("interactionId"),
            "key": it.get("key"),
            "name": it.get("name"),
            "status": it.get("status"),
            "versionNumber": it.get("versionNumber") or it.get("version") or it.get("definitionVersion"),
            "createdDate": it.get("createdDate"),
            "modifiedDate": it.get("modifiedDate"),
            "_raw": it if DEBUG_REST else None
        }

    normed = [norm_item(x) for x in items]
    raw_small = body if DEBUG_REST else {"note": "raw suppressed (enable DEBUG_REST=true to include)"}

    return {
        "count": len(normed),
        "page": page,
        "pageSizeRequested": page_size_req,
        "pageSizeUsed": page_size_eff,
        "items": normed,
        "raw": raw_small,
        "warnings": warnings
    }

def _resolve_item_by_key(journey_key: str, version_number: Optional[int]) -> Tuple[Optional[dict], List[str]]:
    warnings: List[str] = []
    journey_key = (journey_key or "").strip()
    if not journey_key:
        return None, ["Empty key value after 'key:' prefix"]

    # suppress 404 warnings here; key lookups are often probes
    res = search_journeys(
        name_or_description=None,
        status=None,
        journey_id=None,
        key=journey_key,
        most_recent_only=False,
        extras="",
        page=1,
        page_size=MAX_PAGE_SIZE,
        warn_on_404=False,
    )
    warnings.extend(res.get("warnings", []))
    items = res.get("items") or []

    if not items:
        return None, warnings

    k = journey_key.lower()
    matches = [it for it in items if (it.get("key") or "").lower() == k] or items

    if version_number is not None:
        target = int(version_number)
        for it in matches:
            if _safe_int(it.get("versionNumber")) == target:
                return it, warnings
        warnings.append(f"Key matched but versionNumber={target} not found in search results.")
        return None, warnings

    def vn(it: dict) -> int:
        v = _safe_int(it.get("versionNumber"))
        return v if v is not None else -1

    return max(matches, key=vn), warnings

def _fetch_journey_body(id_or_key: str, version_number: Optional[int], extras: Optional[str]) -> Tuple[dict, List[str]]:
    """
    Fetches the SFMC journey payload (dict) + warnings.
    This is used internally for summary/topology so we don't rely on DEBUG_REST/raw passthrough.
    """
    if not id_or_key:
        raise ValueError("idOrKey is required")

    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    warnings: List[str] = []
    extras_eff = _sanitize_extras(extras, warnings)

    id_or_key = str(id_or_key).strip()
    journey_id = None
    resolved_version = version_number

    if id_or_key.lower().startswith("key:"):
        key_val = id_or_key.split(":", 1)[1].strip()

        item, w = _resolve_item_by_key(key_val, version_number)
        warnings.extend(w)

        if item and item.get("id"):
            journey_id = str(item["id"]).strip()
            resolved_version = None  # avoid double-versioning when resolved by search item
        else:
            if _looks_like_guid(key_val):
                warnings.append("idOrKey used 'key:' but no key match found; treating value as a journey id.")
                journey_id = key_val
            else:
                raise FileNotFoundError("Journey not found for provided idOrKey")
    else:
        journey_id = id_or_key

    if not journey_id:
        raise FileNotFoundError("Journey not found for provided idOrKey")

    path = f"/interactions/{quote(str(journey_id), safe='')}"

    qs = []
    if resolved_version is not None:
        qs.append(f"versionNumber={int(resolved_version)}")
    if extras_eff:
        qs.append(f"extras={quote(extras_eff)}")

    url = _build_interactions_url(rest_base, path)
    if qs:
        url += "?" + "&".join(qs)

    status_code, body = _http_json("GET", url, headers=headers, payload=None)
    if status_code == 404:
        raise FileNotFoundError("Journey not found for provided idOrKey")
    if status_code < 200 or status_code >= 300:
        raise RuntimeError(f"getJourney failed ({status_code}): {body}")

    if not isinstance(body, dict):
        raise RuntimeError("Unexpected SFMC response shape (expected JSON object)")

    return body, warnings

def get_journey(id_or_key: str, version_number: Optional[int], extras: Optional[str]) -> dict:
    body, warnings = _fetch_journey_body(id_or_key=id_or_key, version_number=version_number, extras=extras)

    # counts + summaries
    activities_count = None
    if "activities" in body:
        a = body.get("activities")
        if isinstance(a, list):
            activities_count = len(a)
        elif isinstance(a, dict):
            inner = a.get("activities")
            if isinstance(inner, dict):
                activities_count = len(inner or {})
            elif isinstance(inner, list):
                activities_count = len(inner)
            else:
                try:
                    activities_count = len(a)
                except Exception:
                    activities_count = None

    activities_summary = None
    if isinstance(body.get("activities"), list) or isinstance(body.get("triggers"), list):
        activities_summary = _build_activities_summary(body, max_items=ACTIVITY_SUMMARY_MAX_ITEMS)

    version_out = body.get("versionNumber") or body.get("version") or body.get("definitionVersion")
    raw_out = body if DEBUG_REST else {"note": "raw suppressed (set DEBUG_REST=true to include)"}

    return {
        "id": body.get("id"),
        "key": body.get("key"),
        "name": body.get("name"),
        "status": body.get("status"),
        "versionNumber": version_out,
        "activitiesCount": activities_count,
        "activitiesSummary": activities_summary,
        "raw": raw_out,
        "warnings": warnings
    }

def list_journey_versions(id_or_key: str, page_size: int = 50) -> dict:
    if not id_or_key:
        raise ValueError("idOrKey is required")

    id_or_key = str(id_or_key).strip()

    base_kwargs = {
        "name_or_description": None,
        "status": None,
        "journey_id": None,
        "key": None,
        "most_recent_only": False,
        "extras": "",
        "page": 1,
        "page_size": page_size,
    }

    warnings: List[str] = []

    if id_or_key.lower().startswith("key:"):
        key_val = id_or_key.split(":", 1)[1].strip()
        if not key_val:
            raise ValueError("idOrKey starts with 'key:' but key is empty")

        kwargs = dict(base_kwargs)
        kwargs["key"] = key_val
        res = search_journeys(**kwargs)
        warnings.extend(res.get("warnings", []))

        if (res.get("count") or 0) == 0 and _looks_like_guid(key_val):
            warnings.append("idOrKey used 'key:' but no key match found; treating value as a journey id.")
            kwargs2 = dict(base_kwargs)
            kwargs2["journey_id"] = key_val
            res2 = search_journeys(**kwargs2)
            warnings.extend(res2.get("warnings", []))
            res = res2
    else:
        kwargs = dict(base_kwargs)
        kwargs["journey_id"] = id_or_key
        res = search_journeys(**kwargs)
        warnings.extend(res.get("warnings", []))

    items = res.get("items") or []
    if not items:
        raise FileNotFoundError("No journey versions found for provided idOrKey")

    versions = []
    for it in items:
        vn_int = _safe_int(it.get("versionNumber"))
        versions.append({
            "versionNumber": vn_int,
            "status": it.get("status"),
            "modifiedDate": it.get("modifiedDate")
        })

    versions_sorted = sorted(versions, key=lambda x: (x["versionNumber"] is None, x["versionNumber"] or 0))

    first = items[0] if items else {}
    return {
        "id": first.get("id"),
        "key": first.get("key"),
        "name": first.get("name"),
        "versions": versions_sorted,
        "raw": res.get("raw"),
        "warnings": warnings
    }

def get_journey_audit_log(id_or_key: str, action: str, page: int, page_size: int) -> dict:
    if not id_or_key:
        raise ValueError("idOrKey is required")
    action = (action or "all").strip().lower()

    allowed_actions = {"all", "create", "modify", "activate", "deactivate", "stop", "delete"}
    if action not in allowed_actions:
        raise ValueError(f"action must be one of {sorted(list(allowed_actions))}")

    warnings: List[str] = []
    id_or_key = str(id_or_key).strip()

    if id_or_key.lower().startswith("key:"):
        j = get_journey(id_or_key=id_or_key, version_number=None, extras="")
        journey_id = j.get("id")
        warnings.extend(j.get("warnings", []))
        if not journey_id:
            raise RuntimeError("Could not resolve journey id for audit log (missing id in getJourney response)")
    else:
        journey_id = id_or_key

    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    page = _clamp_page(page)
    page_size_req, page_size_eff = _clamp_page_size(page_size, cap=MAX_PAGE_SIZE, default=50)

    qs = [f"$page={page}", f"$pageSize={page_size_eff}"]

    path = f"/interactions/{quote(journey_id, safe='')}/audit/{quote(action, safe='')}"
    url = _build_interactions_url(rest_base, path) + "?" + "&".join(qs)

    status_code, body = _http_json("GET", url, headers=headers, payload=None)
    if status_code == 404:
        raise FileNotFoundError("Audit log not found for provided journey id/key")
    if status_code < 200 or status_code >= 300:
        raise RuntimeError(f"getJourneyAuditLog failed ({status_code}): {body}")

    items = []
    if isinstance(body, dict):
        if isinstance(body.get("items"), list):
            items = body.get("items")
        elif isinstance(body.get("Results"), list):
            items = body.get("Results")
        elif isinstance(body.get("results"), list):
            items = body.get("results")
        elif isinstance(body.get("entries"), list):
            items = body.get("entries")

    raw_small = body if DEBUG_REST else {"note": "raw suppressed (enable DEBUG_REST=true to include)"}

    return {
        "journeyId": journey_id,
        "action": action,
        "page": page,
        "pageSizeRequested": page_size_req,
        "pageSizeUsed": page_size_eff,
        "items": items,
        "raw": raw_small,
        "warnings": warnings
    }

# -----------------------------
# NEW: Summarize + Topology helpers
# -----------------------------
_COMM_TYPES = {"EMAILV2", "EMAIL", "SMSSYNC", "SMS", "PUSH", "PUSHNOTIFICATION", "WHATSAPP", "LINE"}
_DECISION_TYPES = {"MULTICRITERIADECISION", "ENGAGEMENTDECISION", "SPLIT", "RANDOMSPLIT", "DECISION"}
_WAIT_TYPES = {"WAIT", "WAITBYDURATION", "WAITUNTIL"}

def _extract_activities_and_triggers(body: dict) -> Tuple[List[dict], List[dict]]:
    acts = body.get("activities")
    trigs = body.get("triggers")
    activities = acts if isinstance(acts, list) else []
    triggers = trigs if isinstance(trigs, list) else []
    return activities, triggers

def _count_by_type(items: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        t = (it.get("type") or "UNKNOWN")
        counts[t] = counts.get(t, 0) + 1
    return counts

def _scan_refs(obj: Any, allow_keys: Set[str], max_items: int, max_depth: int) -> Dict[str, Any]:
    """
    Iterative scan for specific reference-like keys within nested dict/list structures.
    Returns a small dict of found key->value (first wins).
    """
    found: Dict[str, Any] = {}
    if obj is None:
        return found

    stack: List[Tuple[Any, int]] = [(obj, 0)]
    steps = 0

    while stack and steps < max_items:
        cur, depth = stack.pop()
        steps += 1

        if depth > max_depth:
            continue

        if isinstance(cur, dict):
            for k, v in cur.items():
                if len(found) >= len(allow_keys):
                    return found
                if k in allow_keys and k not in found:
                    found[k] = v
                # continue scanning
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))

    return found

def _summarize_journey(body: dict, warnings: List[str]) -> dict:
    activities, triggers = _extract_activities_and_triggers(body)

    by_type = _count_by_type(activities)
    by_type_sorted = sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))
    top_types = [{"type": t, "count": c} for t, c in by_type_sorted[:12]]

    comms = []
    decisions = []
    waits = []

    # keys commonly holding asset identifiers in activity configuration-ish shapes
    allow_ref_keys = {
        "emailId", "emailID", "email", "emailDefinitionId",
        "smsId", "smsID", "messageId", "messageID",
        "assetId", "assetID", "contentId", "contentID",
        "definitionId", "definitionKey", "key"
    }

    max_list = min(max(ACTIVITY_SUMMARY_MAX_ITEMS, 1), 500)

    for a in activities[:max_list]:
        if not isinstance(a, dict):
            continue
        t = str(a.get("type") or "").upper()
        a_out = {
            "id": a.get("id"),
            "key": a.get("key"),
            "name": a.get("name"),
            "type": a.get("type"),
        }

        # best-effort: look for references in config-ish fields
        config_blob = a.get("configuration") or a.get("config") or a.get("metaData") or a
        refs = _scan_refs(config_blob, allow_ref_keys, max_items=REF_SCAN_MAX_ITEMS, max_depth=REF_SCAN_MAX_DEPTH)
        if refs:
            # keep small: only include up to 8 keys
            small_refs = {}
            for k in sorted(refs.keys())[:8]:
                small_refs[k] = refs[k]
            a_out["refs"] = small_refs

        if t in _COMM_TYPES:
            comms.append(a_out)
        if t in _WAIT_TYPES:
            waits.append(a_out)
        if t in _DECISION_TYPES or "DECISION" in t or "SPLIT" in t:
            decisions.append(a_out)

    summary = {
        "journey": {
            "id": body.get("id"),
            "key": body.get("key"),
            "name": body.get("name"),
            "status": body.get("status"),
            "versionNumber": body.get("versionNumber") or body.get("version") or body.get("definitionVersion"),
        },
        "counts": {
            "activitiesTotal": len(activities),
            "triggersTotal": len(triggers),
            "byType": by_type,
        },
        "topTypes": top_types,
        "entrySources": [
            {"id": t.get("id"), "key": t.get("key"), "name": t.get("name"), "type": t.get("type")}
            for t in triggers[:50] if isinstance(t, dict)
        ],
        "communications": {
            "count": len(comms),
            "items": comms[:80],  # keep payload sane
            "truncated": len(comms) > 80
        },
        "decisions": {
            "count": len(decisions),
            "items": decisions[:80],
            "truncated": len(decisions) > 80
        },
        "waits": {
            "count": len(waits),
            "items": waits[:80],
            "truncated": len(waits) > 80
        },
    }

    if "activities" not in body:
        warnings.append("Journey payload did not include 'activities'. Did you request extras='activities'?")

    return summary

def _build_topology(body: dict, warnings: List[str], max_nodes_req: Optional[int], max_edges_req: Optional[int]) -> dict:
    activities, triggers = _extract_activities_and_triggers(body)

    max_nodes = TOPOLOGY_MAX_NODES
    max_edges = TOPOLOGY_MAX_EDGES

    if isinstance(max_nodes_req, int) and max_nodes_req > 0:
        max_nodes = min(max_nodes_req, TOPOLOGY_MAX_NODES)
    if isinstance(max_edges_req, int) and max_edges_req > 0:
        max_edges = min(max_edges_req, TOPOLOGY_MAX_EDGES)

    nodes = []
    node_key_set: Set[str] = set()

    def add_node(k: Optional[str], name: Optional[str], typ: Optional[str], _id: Optional[str], kind: str = "activity"):
        if not k:
            return
        if k in node_key_set:
            return
        if len(nodes) >= max_nodes:
            return
        node_key_set.add(k)
        nodes.append({
            "key": k,
            "name": name,
            "type": typ,
            "id": _id,
            "kind": kind
        })

    # add trigger nodes (if present)
    for t in triggers:
        if not isinstance(t, dict):
            continue
        add_node(t.get("key") or t.get("id"), t.get("name"), t.get("type"), t.get("id"), kind="trigger")

    # add activity nodes
    for a in activities:
        if not isinstance(a, dict):
            continue
        add_node(a.get("key"), a.get("name"), a.get("type"), a.get("id"), kind="activity")
        if len(nodes) >= max_nodes:
            break

    edges = []
    edge_truncated = False

    for a in activities:
        if not isinstance(a, dict):
            continue
        src = a.get("key")
        outs = a.get("outcomes")
        if not isinstance(outs, list):
            continue
        for o in outs:
            if not isinstance(o, dict):
                continue
            if len(edges) >= max_edges:
                edge_truncated = True
                break
            dst = o.get("next")
            md = o.get("metaData") if isinstance(o.get("metaData"), dict) else {}
            edges.append({
                "from": src,
                "to": dst,
                "outcomeKey": o.get("key"),
                "invalid": md.get("invalid") if isinstance(md, dict) else None
            })
        if edge_truncated:
            break

    # compute basic graph metrics (best-effort)
    incoming: Dict[str, int] = {}
    outgoing: Dict[str, int] = {}
    for e in edges:
        f = e.get("from")
        t = e.get("to")
        if f:
            outgoing[f] = outgoing.get(f, 0) + 1
        if t:
            incoming[t] = incoming.get(t, 0) + 1

    # If triggers don't encode a "next" relationship, fall back to "nodes with no incoming" as potential starts.
    start_candidates = [n["key"] for n in nodes if n.get("key") and incoming.get(n["key"], 0) == 0]
    start_candidates = start_candidates[:20]

    if "activities" not in body:
        warnings.append("Journey payload did not include 'activities'. Did you request extras='activities'?")

    if len(nodes) >= max_nodes and (len(activities) + len(triggers)) > len(nodes):
        warnings.append(f"Topology nodes truncated to max_nodes={max_nodes}. Increase TOPOLOGY_MAX_NODES if safe.")
    if edge_truncated:
        warnings.append(f"Topology edges truncated to max_edges={max_edges}. Increase TOPOLOGY_MAX_EDGES if safe.")

    return {
        "journey": {
            "id": body.get("id"),
            "key": body.get("key"),
            "name": body.get("name"),
            "status": body.get("status"),
            "versionNumber": body.get("versionNumber") or body.get("version") or body.get("definitionVersion"),
        },
        "limits": {
            "maxNodes": max_nodes,
            "maxEdges": max_edges
        },
        "metrics": {
            "nodesReturned": len(nodes),
            "edgesReturned": len(edges),
            "startCandidates": start_candidates
        },
        "nodes": nodes,
        "edges": edges,
    }

# -----------------------------
# Tool handlers (Bedrock router)
# -----------------------------
def _handle_search(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        output = search_journeys(
            name_or_description=params.get("nameOrDescription"),
            status=params.get("status"),
            journey_id=params.get("id"),
            key=params.get("key"),
            most_recent_only=bool(params.get("mostRecentVersionOnly", True)),
            extras=params.get("extras"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
        )
        return 200, {"ok": True, "tool": "journey_search", "input": params, "output": output, "warnings": output.get("warnings", [])}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("searchJourneys failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_get(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        id_or_key = params.get("idOrKey")
        if not id_or_key:
            return 400, {"ok": False, "error": "idOrKey is required"}
        output = get_journey(
            id_or_key=str(id_or_key),
            version_number=params.get("versionNumber"),
            extras=params.get("extras"),
        )
        return 200, {"ok": True, "tool": "journey_get", "input": params, "output": output, "warnings": output.get("warnings", [])}
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("getJourney failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_versions(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        id_or_key = params.get("idOrKey")
        if not id_or_key:
            return 400, {"ok": False, "error": "idOrKey is required"}
        output = list_journey_versions(
            id_or_key=str(id_or_key),
            page_size=int(params.get("pageSize") or 50),
        )
        return 200, {"ok": True, "tool": "journey_versions", "input": params, "output": output, "warnings": output.get("warnings", [])}
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("listJourneyVersions failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_audit(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        id_or_key = params.get("idOrKey")
        if not id_or_key:
            return 400, {"ok": False, "error": "idOrKey is required"}
        output = get_journey_audit_log(
            id_or_key=str(id_or_key),
            action=str(params.get("action") or "all"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 50),
        )
        return 200, {"ok": True, "tool": "journey_audit", "input": params, "output": output, "warnings": output.get("warnings", [])}
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("getJourneyAuditLog failed")
        return 500, {"ok": False, "error": str(e)}

# NEW: summarizeJourney
def _handle_summarize(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        id_or_key = params.get("idOrKey")
        if not id_or_key:
            return 400, {"ok": False, "error": "idOrKey is required"}

        # Force activities for usefulness; still allow allowlisted extras if you pass them explicitly
        extras = params.get("extras") or "activities"

        body, warnings = _fetch_journey_body(
            id_or_key=str(id_or_key),
            version_number=params.get("versionNumber"),
            extras=extras,
        )

        out = _summarize_journey(body, warnings)
        return 200, {"ok": True, "tool": "journey_summarize", "input": params, "output": out, "warnings": warnings}
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("summarizeJourney failed")
        return 500, {"ok": False, "error": str(e)}

# NEW: journeyTopology
def _handle_topology(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        id_or_key = params.get("idOrKey")
        if not id_or_key:
            return 400, {"ok": False, "error": "idOrKey is required"}

        extras = params.get("extras") or "activities"
        max_nodes = params.get("maxNodes")
        max_edges = params.get("maxEdges")

        body, warnings = _fetch_journey_body(
            id_or_key=str(id_or_key),
            version_number=params.get("versionNumber"),
            extras=extras,
        )

        topo = _build_topology(body, warnings, max_nodes_req=max_nodes, max_edges_req=max_edges)
        return 200, {"ok": True, "tool": "journey_topology", "input": params, "output": topo, "warnings": warnings}
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("journeyTopology failed")
        return 500, {"ok": False, "error": str(e)}

# -----------------------------
# Lambda entrypoint
# -----------------------------
def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list((event or {}).keys()) if isinstance(event, dict) else [])

    # Bedrock Action Group invocation
    if isinstance(event, dict) and _is_bedrock_event(event):
        api_path = _get_api_path(event)
        params = _parse_bedrock_params(event)
        logger.info("Bedrock apiPath=%s httpMethod=%s", api_path, _get_http_method(event))
        logger.info("Parsed Bedrock params: %s", params)

        p = (api_path or "").lower()

        if p == "/searchjourneys":
            status, body = _handle_search(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        if p == "/getjourney":
            status, body = _handle_get(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        if p == "/listjourneyversions":
            status, body = _handle_versions(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        if p == "/getjourneyauditlog":
            status, body = _handle_audit(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        # NEW routes
        if p == "/summarizejourney":
            status, body = _handle_summarize(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        if p == "/journeytopology":
            status, body = _handle_topology(params)
            wrapped = {"statusCode": status, **body}
            return _bedrock_actiongroup_response(event, wrapped, http_code=status)

        wrapped = {"statusCode": 400, "ok": False, "error": f"Unknown apiPath: {api_path}"}
        return _bedrock_actiongroup_response(event, wrapped, http_code=400)

    # Direct invoke (API Gateway-style)
    body_in = (event or {}).get("body") if isinstance(event, dict) else None
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event if isinstance(event, dict) else {}).lower()

    if path == "/searchjourneys":
        status, body = _handle_search(params)
        return _json_response(body, status)

    if path == "/getjourney":
        status, body = _handle_get(params)
        return _json_response(body, status)

    if path == "/listjourneyversions":
        status, body = _handle_versions(params)
        return _json_response(body, status)

    if path == "/getjourneyauditlog":
        status, body = _handle_audit(params)
        return _json_response(body, status)

    # NEW direct routes
    if path == "/summarizejourney":
        status, body = _handle_summarize(params)
        return _json_response(body, status)

    if path == "/journeytopology":
        status, body = _handle_topology(params)
        return _json_response(body, status)

    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
