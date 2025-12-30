import os
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Guardrails (hard caps)
# -----------------------------
MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "50"))
AUTOMATION_SEARCH_MAX_ITEMS = int(os.getenv("AUTOMATION_SEARCH_MAX_ITEMS", "250"))
QUERY_SEARCH_MAX_ITEMS = int(os.getenv("QUERY_SEARCH_MAX_ITEMS", "250"))
IMPORT_SEARCH_MAX_ITEMS = int(os.getenv("IMPORT_SEARCH_MAX_ITEMS", "250"))
REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "30"))

SUMMARY_TEXT_TRUNCATE = int(os.getenv("SUMMARY_TEXT_TRUNCATE", "500"))
DETAILS_MAX_HARD_CAP = int(os.getenv("ACTIVITY_DETAILS_MAX_HARD_CAP", "25"))

# When resolving query/import definitions by name/key (used by activityDetails fan-out),
# keep this smaller than full list scans to reduce latency.
RESOLVE_QUERY_SCAN_MAX = int(os.getenv("RESOLVE_QUERY_SCAN_MAX", str(min(QUERY_SEARCH_MAX_ITEMS, 200))))
RESOLVE_IMPORT_SCAN_MAX = int(os.getenv("RESOLVE_IMPORT_SCAN_MAX", str(min(IMPORT_SEARCH_MAX_ITEMS, 200))))

# Fuzzy fallback (name contains) for resolving definitions from automation task names.
# This only accepts the result if there is exactly ONE unique match within the scan cap.
RESOLVE_NAME_CONTAINS_FALLBACK = str(os.getenv("RESOLVE_NAME_CONTAINS_FALLBACK", "true")).strip().lower() in ("true", "1", "yes", "y")

SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
}

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

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
            "responseBody": {"application/json": {"body": json.dumps(body_obj)}},
        },
    }

def _is_bedrock_event(event: dict) -> bool:
    return "messageVersion" in event and "response" not in event

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

def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}

def _looks_like_guid(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    s = val.strip()
    if not s:
        return False
    return bool(_GUID_RE.match(s))

def _norm_name_key(s: str) -> str:
    return (s or "").strip().lower()

# -----------------------------
# Bedrock param extraction
# -----------------------------
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

    aj = content.get("application/json") or content.get("application_json") or {}
    if isinstance(aj, dict):
        props = aj.get("properties")
        if isinstance(props, list):
            for it in props:
                name = it.get("name")
                if not name:
                    continue
                out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            return out

        body = aj.get("body")
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

def _clamp_page_size(page_size: Any, cap: int = MAX_PAGE_SIZE, default: int = 25) -> int:
    try:
        ps = int(page_size)
    except Exception:
        ps = default
    if ps < 1:
        ps = 1
    if ps > cap:
        ps = cap
    return ps

def _truncate(s: Any, max_len: int = SUMMARY_TEXT_TRUNCATE) -> Any:
    if s is None:
        return None
    if not isinstance(s, str):
        return s
    return s if len(s) <= max_len else (s[:max_len] + "…")

def _pick(d: dict, keys: List[str]) -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return None

def _name_matches(name: str, query: str, op: str) -> bool:
    name = (name or "")
    query = (query or "")
    op = (op or "contains").strip().lower()
    n = name.lower()
    q = query.lower()
    if op in ("equals", "eq"):
        return n == q
    if op in ("startswith", "starts_with", "starts"):
        return n.startswith(q)
    return q in n

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

def _derive_rest_from_auth(auth_base: str) -> str:
    return _norm_base(auth_base.replace(".auth.", ".rest."))

def _get_sfmc_bases(secret: dict) -> Tuple[str, str]:
    auth_base = _norm_base(
        os.getenv("SFMC_AUTH_BASE_URL", "")
        or secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
        or secret.get("authUrl", "")
    )
    if not auth_base:
        raise ValueError("Missing auth base URL (set SFMC_AUTH_BASE_URL or secret.auth_url/auth_base_url)")
    rest_base = _norm_base(
        os.getenv("SFMC_REST_BASE_URL", "")
        or secret.get("rest_base_url", "")
        or secret.get("rest_url", "")
        or secret.get("restUrl", "")
    ) or _derive_rest_from_auth(auth_base)
    return auth_base, rest_base

def _enforce_account_guardrail(secret: dict) -> None:
    if not SFMC_ALLOWED_ACCOUNT_ID:
        return
    acct = str(secret.get("account_id") or secret.get("accountId") or "").strip()
    if not acct:
        raise ValueError("Guardrail: SFMC_ALLOWED_ACCOUNT_ID is set but secret has no account_id/accountId")
    if acct != SFMC_ALLOWED_ACCOUNT_ID:
        raise ValueError(f"Guardrail: account_id {acct} not allowed (expected {SFMC_ALLOWED_ACCOUNT_ID})")

def _get_access_token() -> Tuple[str, str]:
    now = int(time.time())
    if _TOKEN_CACHE["access_token"] and now < int(_TOKEN_CACHE["expires_at"] or 0) - 30:
        return _TOKEN_CACHE["access_token"], _TOKEN_CACHE["rest_base_url"]

    secret = _load_secret_json()
    _enforce_account_guardrail(secret)

    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    account_id = secret.get("account_id") or secret.get("accountId")

    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id and client_secret")

    auth_base, rest_base = _get_sfmc_bases(secret)
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

    token_rest = body.get("rest_instance_url") or body.get("restInstanceUrl")
    if token_rest:
        rest_base = _norm_base(token_rest)

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base

    return access_token, rest_base

# -----------------------------
# Core REST helpers
# -----------------------------
def _get_with_page_params(rest_base: str, path: str, page: int, page_size: int) -> Tuple[int, dict]:
    url1 = f"{rest_base}{path}?$page={page}&$pageSize={page_size}"
    url2 = f"{rest_base}{path}?$page={page}&$pagesize={page_size}"
    url3 = f"{rest_base}{path}?page={page}&pageSize={page_size}"

    access_token, _ = _get_access_token()
    headers = _sfmc_headers(access_token)

    s, b = _http_json("GET", url1, headers=headers, payload=None)
    if 200 <= s < 300:
        return s, b
    s2, b2 = _http_json("GET", url2, headers=headers, payload=None)
    if 200 <= s2 < 300:
        return s2, b2
    return _http_json("GET", url3, headers=headers, payload=None)

def _extract_items(body: dict) -> List[dict]:
    if not isinstance(body, dict):
        return []
    for key in ("items", "Items", "results", "Results", "entry", "entries", "data"):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []

# -----------------------------
# Fast resolvers for Query/Import definition IDs
# -----------------------------
def _find_first_match_in_list(
    path: str,
    match_fn,
    max_scan: int
) -> Tuple[Optional[dict], int]:
    """
    Scan list endpoint until match_fn(item) returns True.
    Stops early on first match. Returns (raw_item, scanned_count).
    """
    _, rest_base = _get_access_token()
    scanned = 0
    fetch_page = 1

    while scanned < max_scan:
        status, body = _get_with_page_params(rest_base, path, fetch_page, MAX_PAGE_SIZE)
        if status < 200 or status >= 300:
            raise RuntimeError(f"List failed ({status}) for {path}: {body}")

        items = _extract_items(body)
        if not items:
            break

        scanned += len(items)

        for it in items:
            try:
                if match_fn(it):
                    return it, scanned
            except Exception:
                continue

        fetch_page += 1

    return None, scanned

def _find_matches_in_list(
    path: str,
    match_fn,
    max_scan: int,
    max_matches: int = 3
) -> Tuple[List[dict], int]:
    """
    Scan list endpoint and collect matches up to max_matches.
    Returns (matches, scanned_count). Stops early if matches reaches max_matches.
    """
    _, rest_base = _get_access_token()
    scanned = 0
    fetch_page = 1
    matches: List[dict] = []

    while scanned < max_scan:
        status, body = _get_with_page_params(rest_base, path, fetch_page, MAX_PAGE_SIZE)
        if status < 200 or status >= 300:
            raise RuntimeError(f"List failed ({status}) for {path}: {body}")

        items = _extract_items(body)
        if not items:
            break

        scanned += len(items)

        for it in items:
            try:
                if match_fn(it):
                    matches.append(it)
                    if len(matches) >= max_matches:
                        return matches, scanned
            except Exception:
                continue

        fetch_page += 1

    return matches, scanned

def _extract_query_definition_id(raw: dict) -> Optional[str]:
    cand = _pick(raw, ["queryDefinitionId", "QueryDefinitionId", "id", "Id"])
    if cand:
        return str(cand)
    return None

def _extract_import_definition_id(raw: dict) -> Optional[str]:
    cand = _pick(raw, ["importDefinitionId", "ImportDefinitionId", "id", "Id"])
    if cand:
        return str(cand)
    return None

def _resolve_query_definition_id(
    *,
    id_candidate: Optional[str],
    customer_key: Optional[str],
    name: Optional[str],
    cache: dict
) -> Tuple[Optional[str], str, List[str]]:
    warnings: List[str] = []

    # 1) direct id attempt (if it already is a QueryDefinitionId)
    if id_candidate and _looks_like_guid(id_candidate):
        try:
            _ = describe_query_activity(str(id_candidate))
            return str(id_candidate), "id", warnings
        except Exception as e:
            if "Describe query failed (404)" not in str(e):
                raise
            warnings.append("id did not resolve as a QueryDefinitionId; attempting customerKey/name resolution.")

    # 2) customerKey
    ck = (customer_key or "").strip()
    if ck:
        if ck in cache.get("queryByCustomerKey", {}):
            return cache["queryByCustomerKey"][ck], "customerKey_cache", warnings

        def _match(it: dict) -> bool:
            it_ck = str(_pick(it, ["customerKey", "CustomerKey", "key", "Key"]) or "").strip()
            return it_ck.lower() == ck.lower()

        raw, scanned = _find_first_match_in_list("/automation/v1/queries", _match, RESOLVE_QUERY_SCAN_MAX)
        if raw:
            qid = _extract_query_definition_id(raw)
            if qid:
                cache.setdefault("queryByCustomerKey", {})[ck] = qid
                return qid, f"customerKey(scanned={scanned})", warnings
        warnings.append(f"Could not resolve QueryDefinitionId from customerKey within scan cap ({RESOLVE_QUERY_SCAN_MAX}).")

    # 3) name (exact)
    nm = (name or "").strip()
    if nm:
        if nm in cache.get("queryByName", {}):
            return cache["queryByName"][nm], "name_cache", warnings

        def _match_exact(it: dict) -> bool:
            it_nm = str(_pick(it, ["name", "Name"]) or "").strip()
            return it_nm.lower() == nm.lower()

        raw, scanned = _find_first_match_in_list("/automation/v1/queries", _match_exact, RESOLVE_QUERY_SCAN_MAX)
        if raw:
            qid = _extract_query_definition_id(raw)
            if qid:
                cache.setdefault("queryByName", {})[nm] = qid
                return qid, f"name_exact(scanned={scanned})", warnings

        # 3b) name (contains) - only accept if unique
        if RESOLVE_NAME_CONTAINS_FALLBACK:
            nm_l = _norm_name_key(nm)

            def _match_contains(it: dict) -> bool:
                it_nm = _norm_name_key(str(_pick(it, ["name", "Name"]) or ""))
                if not it_nm:
                    return False
                # handle either direction (task name may be longer/shorter than definition name)
                return (nm_l in it_nm) or (it_nm in nm_l)

            matches, scanned2 = _find_matches_in_list("/automation/v1/queries", _match_contains, RESOLVE_QUERY_SCAN_MAX, max_matches=3)
            if len(matches) == 1:
                qid = _extract_query_definition_id(matches[0])
                if qid:
                    cache.setdefault("queryByName", {})[nm] = qid
                    return qid, f"name_contains_unique(scanned={scanned2})", warnings
            if len(matches) > 1:
                warnings.append(
                    f"Ambiguous query name contains-match for '{nm}' (found {len(matches)} matches within scan cap); not auto-selecting."
                )

        warnings.append(f"Could not resolve QueryDefinitionId from name within scan cap ({RESOLVE_QUERY_SCAN_MAX}).")

    return None, "unresolved", warnings

def _resolve_import_definition_id(
    *,
    id_candidate: Optional[str],
    customer_key: Optional[str],
    name: Optional[str],
    cache: dict
) -> Tuple[Optional[str], str, List[str]]:
    warnings: List[str] = []

    # 1) direct id attempt (if it already is an ImportDefinitionId)
    if id_candidate and _looks_like_guid(id_candidate):
        try:
            _ = describe_import_activity(str(id_candidate))
            return str(id_candidate), "id", warnings
        except Exception as e:
            if "Describe import failed (404)" not in str(e):
                raise
            warnings.append("id did not resolve as an ImportDefinitionId; attempting customerKey/name resolution.")

    # 2) customerKey
    ck = (customer_key or "").strip()
    if ck:
        if ck in cache.get("importByCustomerKey", {}):
            return cache["importByCustomerKey"][ck], "customerKey_cache", warnings

        def _match(it: dict) -> bool:
            it_ck = str(_pick(it, ["customerKey", "CustomerKey", "key", "Key"]) or "").strip()
            return it_ck.lower() == ck.lower()

        raw, scanned = _find_first_match_in_list("/automation/v1/imports", _match, RESOLVE_IMPORT_SCAN_MAX)
        if raw:
            iid = _extract_import_definition_id(raw) or str(_pick(raw, ["importDefinitionId", "ImportDefinitionId"]) or "")
            iid = iid.strip() or None
            if iid:
                cache.setdefault("importByCustomerKey", {})[ck] = iid
                return iid, f"customerKey(scanned={scanned})", warnings
        warnings.append(f"Could not resolve ImportDefinitionId from customerKey within scan cap ({RESOLVE_IMPORT_SCAN_MAX}).")

    # 3) name (exact)
    nm = (name or "").strip()
    if nm:
        if nm in cache.get("importByName", {}):
            return cache["importByName"][nm], "name_cache", warnings

        def _match_exact(it: dict) -> bool:
            it_nm = str(_pick(it, ["name", "Name"]) or "").strip()
            return it_nm.lower() == nm.lower()

        raw, scanned = _find_first_match_in_list("/automation/v1/imports", _match_exact, RESOLVE_IMPORT_SCAN_MAX)
        if raw:
            iid = _extract_import_definition_id(raw) or str(_pick(raw, ["importDefinitionId", "ImportDefinitionId"]) or "")
            iid = iid.strip() or None
            if iid:
                cache.setdefault("importByName", {})[nm] = iid
                return iid, f"name_exact(scanned={scanned})", warnings

        # 3b) name (contains) - only accept if unique
        if RESOLVE_NAME_CONTAINS_FALLBACK:
            nm_l = _norm_name_key(nm)

            def _match_contains(it: dict) -> bool:
                it_nm = _norm_name_key(str(_pick(it, ["name", "Name"]) or ""))
                if not it_nm:
                    return False
                return (nm_l in it_nm) or (it_nm in nm_l)

            matches, scanned2 = _find_matches_in_list("/automation/v1/imports", _match_contains, RESOLVE_IMPORT_SCAN_MAX, max_matches=3)
            if len(matches) == 1:
                raw0 = matches[0]
                iid = _extract_import_definition_id(raw0) or str(_pick(raw0, ["importDefinitionId", "ImportDefinitionId"]) or "")
                iid = iid.strip() or None
                if iid:
                    cache.setdefault("importByName", {})[nm] = iid
                    return iid, f"name_contains_unique(scanned={scanned2})", warnings
            if len(matches) > 1:
                warnings.append(
                    f"Ambiguous import name contains-match for '{nm}' (found {len(matches)} matches within scan cap); not auto-selecting."
                )

        warnings.append(f"Could not resolve ImportDefinitionId from name within scan cap ({RESOLVE_IMPORT_SCAN_MAX}).")

    return None, "unresolved", warnings

# -----------------------------
# Schedule helpers
# -----------------------------
def _extract_schedule_obj(obj: dict) -> Optional[dict]:
    if not isinstance(obj, dict):
        return None
    s = _pick(obj, ["schedule", "Schedule", "scheduleDefinition", "ScheduleDefinition", "scheduleInfo", "ScheduleInfo"])
    if isinstance(s, dict):
        return s
    s2 = obj.get("schedule") if isinstance(obj.get("schedule"), dict) else None
    return s2 if isinstance(s2, dict) else None

def _norm_schedule(s: dict) -> Optional[dict]:
    if not isinstance(s, dict):
        return None

    out = {}
    for k in [
        "scheduleStatus", "ScheduleStatus", "status", "Status",
        "startDate", "StartDate", "startTime", "StartTime",
        "endDate", "EndDate", "endTime", "EndTime",
        "timezone", "timeZone", "TimeZone", "timezoneId", "TimezoneId",
        "recurrenceType", "RecurrenceType",
        "recurrenceInterval", "RecurrenceInterval",
        "weeklyDays", "WeeklyDays",
        "monthlyDay", "MonthlyDay",
        "monthlyWeek", "MonthlyWeek",
        "monthlyWeekday", "MonthlyWeekday",
        "icalRecur", "iCalRecur", "IcalRecur",
        "nextRunTime", "NextRunTime",
        "lastRunTime", "LastRunTime",
    ]:
        if k in s and s.get(k) is not None:
            out[k[0].lower() + k[1:]] = s.get(k)

    return out if out else s

def _schedule_status_from_obj(obj: dict) -> Optional[Any]:
    s = _extract_schedule_obj(obj)
    if not isinstance(s, dict):
        return None
    return _pick(s, ["scheduleStatus", "ScheduleStatus", "status", "Status"])

def _lookup_automation_list_item(automation_id: str) -> Tuple[Optional[dict], List[str]]:
    warnings: List[str] = []
    _, rest_base = _get_access_token()

    scanned = 0
    fetch_page = 1

    while scanned < AUTOMATION_SEARCH_MAX_ITEMS:
        status, body = _get_with_page_params(rest_base, "/automation/v1/automations", fetch_page, MAX_PAGE_SIZE)
        if status < 200 or status >= 300:
            warnings.append(f"List lookup failed ({status}); cannot resolve list metadata.")
            return None, warnings

        items = _extract_items(body)
        if not items:
            break

        scanned += len(items)

        for it in items:
            it_id = str(_pick(it, ["id", "Id", "automationId", "automationID"]) or "")
            if it_id and str(automation_id) == it_id:
                return it, warnings

        fetch_page += 1

    if scanned >= AUTOMATION_SEARCH_MAX_ITEMS:
        warnings.append(f"List lookup scan cap hit at {AUTOMATION_SEARCH_MAX_ITEMS} items; list metadata may be incomplete.")
    return None, warnings

# -----------------------------
# Normalizers
# -----------------------------
def _norm_automation_item(it: dict) -> dict:
    sched_status = _schedule_status_from_obj(it)
    return {
        "id": _pick(it, ["id", "Id", "automationId", "automationID"]),
        "name": _pick(it, ["name", "Name"]),
        "key": _pick(it, ["key", "Key", "customerKey", "CustomerKey"]),
        "status": _pick(it, ["status", "Status"]),
        "statusName": _pick(it, ["statusName", "StatusName", "statusDescription"]),
        "modifiedDate": _pick(it, ["modifiedDate", "ModifiedDate", "lastModifiedDate", "updatedDate"]),
        "createdDate": _pick(it, ["createdDate", "CreatedDate"]),
        "lastRunTime": _pick(it, ["lastRunTime", "LastRunTime", "lastRunDateTime", "LastRunDateTime"]),
        "lastRunInstanceId": _pick(it, ["lastRunInstanceId", "LastRunInstanceId"]),
        "scheduleStatus": sched_status,
    }

def _norm_query_item(it: dict) -> dict:
    definition_id = _pick(it, ["queryDefinitionId", "QueryDefinitionId", "id", "Id"])
    return {
        "id": definition_id,
        "definitionId": definition_id,
        "name": _pick(it, ["name", "Name"]),
        "key": _pick(it, ["customerKey", "CustomerKey", "key", "Key"]),
        "targetKey": _pick(it, ["targetKey", "TargetKey", "targetCustomerKey"]),
        "modifiedDate": _pick(it, ["modifiedDate", "ModifiedDate", "lastModifiedDate", "updatedDate"]),
    }

def _norm_import_item(it: dict) -> dict:
    definition_id = _pick(it, ["importDefinitionId", "ImportDefinitionId", "id", "Id"])
    return {
        "id": definition_id,
        "definitionId": definition_id,
        "name": _pick(it, ["name", "Name"]),
        "key": _pick(it, ["customerKey", "CustomerKey", "key", "Key"]),
        "destinationObjectId": _pick(it, ["destinationObjectId", "DestinationObjectId", "destinationId"]),
        "modifiedDate": _pick(it, ["modifiedDate", "ModifiedDate", "lastModifiedDate", "updatedDate"]),
        "importDefinitionId": _pick(it, ["importDefinitionId", "ImportDefinitionId"]),
    }

def _norm_automation_task(t: dict, seq: int) -> dict:
    return {
        "seq": seq,
        "name": _pick(t, ["name", "Name"]),
        "type": _pick(t, ["activityType", "ActivityType", "type", "Type"]),
        "activityObjectId": _pick(t, ["activityObjectId", "ActivityObjectId", "objectId", "ObjectID", "id", "Id"]),
        "activityId": _pick(t, ["activityId", "ActivityId"]),
        "objectId": _pick(t, ["objectId", "ObjectID"]),
        "objectTypeId": _pick(t, ["objectTypeId", "ObjectTypeId", "activityObjectTypeId", "ActivityObjectTypeId"]),
        "step": _pick(t, ["step", "Step"]),
    }

def _norm_query_detail(d: dict) -> dict:
    return {
        "id": _pick(d, ["queryDefinitionId", "QueryDefinitionId", "id", "Id"]),
        "name": _pick(d, ["name", "Name"]),
        "key": _pick(d, ["customerKey", "CustomerKey", "key", "Key"]),
        "targetKey": _pick(d, ["targetKey", "TargetKey", "targetCustomerKey"]),
        "targetUpdateType": _pick(d, ["targetUpdateType", "TargetUpdateType", "updateType"]),
        "queryText": _truncate(_pick(d, ["queryText", "QueryText", "sqlText", "SqlText"]), SUMMARY_TEXT_TRUNCATE),
        "modifiedDate": _pick(d, ["modifiedDate", "ModifiedDate", "lastModifiedDate", "updatedDate"]),
    }

def _norm_import_detail(d: dict) -> dict:
    return {
        "id": _pick(d, ["importDefinitionId", "ImportDefinitionId", "id", "Id"]),
        "name": _pick(d, ["name", "Name"]),
        "key": _pick(d, ["customerKey", "CustomerKey", "key", "Key"]),
        "destinationObjectId": _pick(d, ["destinationObjectId", "DestinationObjectId", "destinationId"]),
        "fileNamingPattern": _truncate(_pick(d, ["fileNamingPattern", "FileNamingPattern", "fileSpec", "FileSpec"]), 250),
        "modifiedDate": _pick(d, ["modifiedDate", "ModifiedDate", "lastModifiedDate", "updatedDate"]),
    }

# -----------------------------
# SFMC read-only operations
# -----------------------------
def _search_capped(path: str, query_text: str, name_operator: str, page: int, page_size: int, max_scan: int, norm_fn, include_raw: bool) -> dict:
    page = _clamp_page(page)
    page_size = _clamp_page_size(page_size)
    scanned = 0
    fetch_page = 1
    matched_summary: List[dict] = []
    matched_raw: List[dict] = []
    warnings: List[str] = []

    _, rest_base = _get_access_token()

    while scanned < max_scan:
        status, body = _get_with_page_params(rest_base, path, fetch_page, MAX_PAGE_SIZE)
        if status < 200 or status >= 300:
            raise RuntimeError(f"List failed ({status}) for {path}: {body}")

        items = _extract_items(body)
        if not items:
            break

        scanned += len(items)

        for it in items:
            nm = str(_pick(it, ["name", "Name"]) or "")
            if query_text and not _name_matches(nm, query_text, name_operator):
                continue
            matched_summary.append(norm_fn(it))
            if include_raw:
                matched_raw.append(it)

        if scanned >= max_scan:
            warnings.append(f"Search scan cap hit at {max_scan} items; results may be incomplete.")
            break

        fetch_page += 1

    total = len(matched_summary)
    start = (page - 1) * page_size
    end = start + page_size

    out = {
        "count": total,
        "page": page,
        "pageSize": page_size,
        "items": matched_summary[start:end] if start < total else [],
        "warnings": warnings,
    }
    if include_raw:
        out["itemsRaw"] = matched_raw[start:end] if start < total else []
    return out

def search_automations(query_text: str, name_operator: str, page: int, page_size: int, status_codes: Optional[List[int]], include_raw: bool) -> dict:
    raw = _search_capped(
        path="/automation/v1/automations",
        query_text=query_text,
        name_operator=name_operator,
        page=page,
        page_size=page_size,
        max_scan=AUTOMATION_SEARCH_MAX_ITEMS,
        norm_fn=_norm_automation_item,
        include_raw=include_raw
    )

    if status_codes:
        try:
            allowed = set(int(x) for x in status_codes)
        except Exception:
            allowed = set()

        if allowed:
            items = raw.get("items", [])
            raw_items = raw.get("itemsRaw", []) if include_raw else None

            filtered_items = []
            filtered_raw_items = [] if include_raw else None

            for idx, it in enumerate(items):
                st = it.get("status")
                try:
                    st_i = int(st)
                except Exception:
                    st_i = None
                if st_i is not None and st_i in allowed:
                    filtered_items.append(it)
                    if include_raw and raw_items is not None and idx < len(raw_items):
                        filtered_raw_items.append(raw_items[idx])

            raw["count"] = len(filtered_items)
            raw["items"] = filtered_items
            if include_raw:
                raw["itemsRaw"] = filtered_raw_items

    return raw

def describe_query_activity(query_definition_id: str) -> dict:
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)
    qid_enc = quote(str(query_definition_id), safe="")
    url = f"{rest_base}/automation/v1/queries/{qid_enc}"
    status, body = _http_json("GET", url, headers=headers, payload=None)
    if status < 200 or status >= 300:
        raise RuntimeError(f"Describe query failed ({status}): {body}")
    return body

def describe_import_activity(import_definition_id: str) -> dict:
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)
    iid_enc = quote(str(import_definition_id), safe="")
    url = f"{rest_base}/automation/v1/imports/{iid_enc}"
    status, body = _http_json("GET", url, headers=headers, payload=None)
    if status < 200 or status >= 300:
        raise RuntimeError(f"Describe import failed ({status}): {body}")
    return body

def describe_automation(
    automation_id: str,
    include_task_summary: bool,
    include_activity_details: bool,
    activity_details_max: int,
    include_raw: bool,
    include_schedule: bool,
) -> dict:
    access_token, rest_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    aid_enc = quote(str(automation_id), safe="")
    url = f"{rest_base}/automation/v1/automations/{aid_enc}"
    status, body = _http_json("GET", url, headers=headers, payload=None)
    if status < 200 or status >= 300:
        if status == 404:
            return _json_response({
                "ok": False,
                "error": "AUTOMATION_NOT_FOUND",
                "automationId": automation_id,
                "hint": "SFMC returned 404. Check MID/BU context or whether this is actually an automation REST id. Try searching automations by name to get the correct id.",
                "sfmc": body
            }, status_code=200)  # keep 200 so Bedrock doesn't treat it as 'API execution failed'

    out: Dict[str, Any] = {
        "automation": _norm_automation_item(body if isinstance(body, dict) else {}),
        "schedule": None,
        "taskSummary": None,
        "activityDetails": [],
        "warnings": [],
    }
    if include_raw:
        out["automationRaw"] = body

    # Decide if we need list lookup to enrich run metadata and/or schedule fallback
    need_list_lookup = False
    for k in ("lastRunTime", "lastRunInstanceId", "scheduleStatus"):
        if out.get("automation", {}).get(k) is None:
            need_list_lookup = True
            break

    norm_sched = None
    sched_raw = None
    if include_schedule:
        sched_raw = _extract_schedule_obj(body if isinstance(body, dict) else {})
        norm_sched = _norm_schedule(sched_raw) if sched_raw else None
        if not norm_sched:
            need_list_lookup = True

    list_item = None
    if need_list_lookup:
        list_item, lw = _lookup_automation_list_item(str(automation_id))
        out["warnings"].extend(lw)

        if list_item:
            list_norm = _norm_automation_item(list_item)

            for k in ("lastRunTime", "lastRunInstanceId", "scheduleStatus"):
                if out["automation"].get(k) is None and list_norm.get(k) is not None:
                    out["automation"][k] = list_norm.get(k)

            if include_raw:
                out["automationListRaw"] = list_item

            if include_schedule and not norm_sched:
                sched_raw = _extract_schedule_obj(list_item)
                norm_sched = _norm_schedule(sched_raw) if sched_raw else None
                if include_raw and sched_raw:
                    out["scheduleRaw"] = sched_raw

    if include_schedule:
        out["schedule"] = norm_sched
        if include_raw and sched_raw and "scheduleRaw" not in out:
            out["scheduleRaw"] = sched_raw
        if out["schedule"] is None:
            out["warnings"].append("Schedule not available for this automation (or not exposed by the API).")

    # Task summary
    if include_task_summary:
        tasks = _pick(body, ["automationTasks", "AutomationTasks", "tasks", "Tasks", "steps", "Steps"]) or []
        if not isinstance(tasks, list):
            tasks = []
        summary = []
        for idx, t in enumerate(tasks, start=1):
            if isinstance(t, dict):
                summary.append(_norm_automation_task(t, idx))
        out["taskSummary"] = {"count": len(summary), "items": summary}

    # Activity detail fan-out (query/import only; capped + resolved)
    if include_activity_details:
        eff_max = int(activity_details_max or 20)
        if eff_max > DETAILS_MAX_HARD_CAP:
            out["warnings"].append(f"activityDetailsMax was clamped from {eff_max} to {DETAILS_MAX_HARD_CAP} (guardrail).")
            eff_max = DETAILS_MAX_HARD_CAP

        tasks_items = (out.get("taskSummary") or {}).get("items", []) if include_task_summary else []
        details = []
        fetched = 0

        resolve_cache: dict = {}

        for it in tasks_items:
            if fetched >= eff_max:
                out["warnings"].append(f"Activity details capped at {eff_max}.")
                break

            atype = str(it.get("type") or "").lower()
            obj_type = it.get("objectTypeId")
            obj_type_s = str(obj_type) if obj_type is not None else ""
            task_name = str(it.get("name") or "").strip()

            aoid = it.get("activityObjectId")
            aoid_s = str(aoid) if aoid is not None else ""

            # Prefer objectTypeId signals when available
            is_query = (obj_type_s == "300") or ("query" in atype)
            is_import = (obj_type_s == "43") or ("import" in atype)

            try:
                if is_query:
                    qid, via, w = _resolve_query_definition_id(
                        id_candidate=aoid_s or None,
                        customer_key=None,
                        name=task_name or None,
                        cache=resolve_cache
                    )
                    out["warnings"].extend(w)

                    if not qid:
                        out["warnings"].append(f"Could not resolve QueryDefinitionId for task '{task_name}' (activityObjectId={aoid_s}).")
                        continue

                    q_raw = describe_query_activity(str(qid))
                    d = {
                        "type": "query",
                        "definitionId": str(qid),
                        "resolvedVia": via,
                        "taskName": task_name,
                        "activityObjectId": aoid_s,
                        "summary": _norm_query_detail(q_raw),
                    }
                    if include_raw:
                        d["raw"] = q_raw
                    details.append(d)
                    fetched += 1

                elif is_import:
                    iid, via, w = _resolve_import_definition_id(
                        id_candidate=aoid_s or None,
                        customer_key=None,
                        name=task_name or None,
                        cache=resolve_cache
                    )
                    out["warnings"].extend(w)

                    if not iid:
                        out["warnings"].append(f"Could not resolve ImportDefinitionId for task '{task_name}' (activityObjectId={aoid_s}).")
                        continue

                    i_raw = describe_import_activity(str(iid))
                    d = {
                        "type": "import",
                        "definitionId": str(iid),
                        "resolvedVia": via,
                        "taskName": task_name,
                        "activityObjectId": aoid_s,
                        "summary": _norm_import_detail(i_raw),
                    }
                    if include_raw:
                        d["raw"] = i_raw
                    details.append(d)
                    fetched += 1

            except Exception as e:
                out["warnings"].append(
                    f"Failed to fetch activity detail for task '{task_name or 'unknown'}' "
                    f"(objectTypeId={obj_type_s}, activityObjectId={aoid_s}): {str(e)}"
                )

        out["activityDetails"] = details

    return out

def automation_summary(
    automation_id: str,
    include_activity_details: bool,
    activity_details_max: int,
    include_raw: bool,
    include_schedule: bool
) -> dict:
    return describe_automation(
        automation_id=automation_id,
        include_task_summary=True,
        include_activity_details=include_activity_details,
        activity_details_max=activity_details_max,
        include_raw=include_raw,
        include_schedule=include_schedule,
    )

def search_query_activities(query_text: str, name_operator: str, page: int, page_size: int, include_raw: bool) -> dict:
    return _search_capped(
        path="/automation/v1/queries",
        query_text=query_text,
        name_operator=name_operator,
        page=page,
        page_size=page_size,
        max_scan=QUERY_SEARCH_MAX_ITEMS,
        norm_fn=_norm_query_item,
        include_raw=include_raw
    )

def search_import_activities(query_text: str, name_operator: str, page: int, page_size: int, include_raw: bool) -> dict:
    return _search_capped(
        path="/automation/v1/imports",
        query_text=query_text,
        name_operator=name_operator,
        page=page,
        page_size=page_size,
        max_scan=IMPORT_SEARCH_MAX_ITEMS,
        norm_fn=_norm_import_item,
        include_raw=include_raw
    )

# -----------------------------
# Tool handlers (Bedrock apiPath routing)
# -----------------------------
def _handle_search_automations(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        qt = params.get("queryText")
        if not qt:
            return 400, {"ok": False, "error": "queryText is required"}

        include_raw = bool(params.get("includeRaw", False))

        requested_ps = params.get("pageSize") or 25
        eff_ps = _clamp_page_size(requested_ps)
        if str(requested_ps) != str(eff_ps):
            params["pageSizeRequested"] = requested_ps
            params["pageSize"] = eff_ps

        out = search_automations(
            query_text=str(qt),
            name_operator=str(params.get("nameOperator") or "contains"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
            status_codes=params.get("statusCodes") if isinstance(params.get("statusCodes"), list) else None,
            include_raw=include_raw,
        )

        warnings = list(out.get("warnings", []))
        if "pageSizeRequested" in params and int(params.get("pageSize")) != int(params.get("pageSizeRequested")):
            warnings.append(f"pageSize was clamped from {params.get('pageSizeRequested')} to {params.get('pageSize')} (guardrail).")

        return 200, {"ok": True, "tool": "automation_search", "input": params, "output": out, "warnings": warnings}
    except Exception as e:
        logger.exception("searchAutomations failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_describe_automation(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        aid = params.get("id") or params.get("automationId")
        if not aid:
            return 400, {"ok": False, "error": "id (automationId) is required"}

        include_raw = bool(params.get("includeRaw", False))
        include_schedule = bool(params.get("includeSchedule", False))

        req_adm = params.get("activityDetailsMax") if params.get("activityDetailsMax") is not None else 20
        eff_adm = int(req_adm)
        if eff_adm > DETAILS_MAX_HARD_CAP:
            eff_adm = DETAILS_MAX_HARD_CAP
        params["activityDetailsMaxRequested"] = req_adm
        params["activityDetailsMax"] = eff_adm

        out = describe_automation(
            automation_id=str(aid),
            include_task_summary=bool(params.get("includeTaskSummary", True)),
            include_activity_details=bool(params.get("includeActivityDetails", False)),
            activity_details_max=int(params.get("activityDetailsMax") or 20),
            include_raw=include_raw,
            include_schedule=include_schedule,
        )
        return 200, {"ok": True, "tool": "automation_describe", "input": params, "output": out, "warnings": out.get("warnings", [])}
    except Exception as e:
        logger.exception("describeAutomation failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_automation_summary(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        aid = params.get("id") or params.get("automationId")
        if not aid:
            return 400, {"ok": False, "error": "id (automationId) is required"}

        include_raw = bool(params.get("includeRaw", False))
        include_schedule = bool(params.get("includeSchedule", True))  # default TRUE for summary

        req_adm = params.get("activityDetailsMax") if params.get("activityDetailsMax") is not None else 20
        eff_adm = int(req_adm)
        if eff_adm > DETAILS_MAX_HARD_CAP:
            eff_adm = DETAILS_MAX_HARD_CAP
        params["activityDetailsMaxRequested"] = req_adm
        params["activityDetailsMax"] = eff_adm

        out = automation_summary(
            automation_id=str(aid),
            include_activity_details=bool(params.get("includeActivityDetails", False)),
            activity_details_max=int(params.get("activityDetailsMax") or 20),
            include_raw=include_raw,
            include_schedule=include_schedule,
        )
        return 200, {"ok": True, "tool": "automation_summary", "input": params, "output": out, "warnings": out.get("warnings", [])}
    except Exception as e:
        logger.exception("automationSummary failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_search_queries(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        qt = params.get("queryText")
        if not qt:
            return 400, {"ok": False, "error": "queryText is required"}

        include_raw = bool(params.get("includeRaw", False))

        requested_ps = params.get("pageSize") or 25
        eff_ps = _clamp_page_size(requested_ps)
        if str(requested_ps) != str(eff_ps):
            params["pageSizeRequested"] = requested_ps
            params["pageSize"] = eff_ps

        out = search_query_activities(
            query_text=str(qt),
            name_operator=str(params.get("nameOperator") or "contains"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
            include_raw=include_raw,
        )

        warnings = list(out.get("warnings", []))
        if "pageSizeRequested" in params and int(params.get("pageSize")) != int(params.get("pageSizeRequested")):
            warnings.append(f"pageSize was clamped from {params.get('pageSizeRequested')} to {params.get('pageSize')} (guardrail).")

        return 200, {"ok": True, "tool": "query_search", "input": params, "output": out, "warnings": warnings}
    except Exception as e:
        logger.exception("searchQueryActivities failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_describe_query(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        # Accept id OR customerKey OR name
        id_candidate = params.get("id") or params.get("queryId") or params.get("queryDefinitionId")
        customer_key = params.get("customerKey") or params.get("key")
        name = params.get("name") or params.get("queryName")

        include_raw = bool(params.get("includeRaw", False))

        if not id_candidate and not customer_key and not name:
            return 400, {"ok": False, "error": "Provide id (queryDefinitionId) OR customerKey OR name"}

        cache: dict = {}
        resolved_id, via, w = _resolve_query_definition_id(
            id_candidate=str(id_candidate) if id_candidate else None,
            customer_key=str(customer_key) if customer_key else None,
            name=str(name) if name else None,
            cache=cache
        )
        if not resolved_id:
            return 404, {"ok": False, "error": "Could not resolve QueryDefinitionId from provided inputs", "warnings": w}

        raw = describe_query_activity(str(resolved_id))
        out = {"query": _norm_query_detail(raw)}
        if include_raw:
            out["queryRaw"] = raw

        return 200, {
            "ok": True,
            "tool": "query_describe",
            "input": params,
            "resolvedId": resolved_id,
            "resolvedVia": via,
            "output": out,
            "warnings": w
        }
    except Exception as e:
        logger.exception("describeQueryActivity failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_search_imports(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        qt = params.get("queryText")
        if not qt:
            return 400, {"ok": False, "error": "queryText is required"}

        include_raw = bool(params.get("includeRaw", False))

        requested_ps = params.get("pageSize") or 25
        eff_ps = _clamp_page_size(requested_ps)
        if str(requested_ps) != str(eff_ps):
            params["pageSizeRequested"] = requested_ps
            params["pageSize"] = eff_ps

        out = search_import_activities(
            query_text=str(qt),
            name_operator=str(params.get("nameOperator") or "contains"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
            include_raw=include_raw
        )

        warnings = list(out.get("warnings", []))
        if "pageSizeRequested" in params and int(params.get("pageSize")) != int(params.get("pageSizeRequested")):
            warnings.append(f"pageSize was clamped from {params.get('pageSizeRequested')} to {params.get('pageSize')} (guardrail).")

        return 200, {"ok": True, "tool": "import_search", "input": params, "output": out, "warnings": warnings}
    except Exception as e:
        logger.exception("searchImportActivities failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_describe_import(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        # Accept id OR customerKey OR name
        id_candidate = params.get("id") or params.get("importId") or params.get("importDefinitionId")
        customer_key = params.get("customerKey") or params.get("key")
        name = params.get("name") or params.get("importName")

        include_raw = bool(params.get("includeRaw", False))

        if not id_candidate and not customer_key and not name:
            return 400, {"ok": False, "error": "Provide id (importDefinitionId) OR customerKey OR name"}

        cache: dict = {}
        resolved_id, via, w = _resolve_import_definition_id(
            id_candidate=str(id_candidate) if id_candidate else None,
            customer_key=str(customer_key) if customer_key else None,
            name=str(name) if name else None,
            cache=cache
        )
        if not resolved_id:
            return 404, {"ok": False, "error": "Could not resolve ImportDefinitionId from provided inputs", "warnings": w}

        raw = describe_import_activity(str(resolved_id))
        out = {"import": _norm_import_detail(raw)}
        if include_raw:
            out["importRaw"] = raw

        return 200, {
            "ok": True,
            "tool": "import_describe",
            "input": params,
            "resolvedId": resolved_id,
            "resolvedVia": via,
            "output": out,
            "warnings": w
        }
    except Exception as e:
        logger.exception("describeImportActivity failed")
        return 500, {"ok": False, "error": str(e)}

# -----------------------------
# Lambda entrypoint
# -----------------------------
def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list(event.keys()))

    # Bedrock Action Group invoke
    if _is_bedrock_event(event):
        api_path = _get_api_path(event).lower()
        params = _parse_bedrock_params(event)
        logger.info("Bedrock apiPath=%s httpMethod=%s", api_path, _get_http_method(event))
        logger.info("Parsed Bedrock params: %s", params)

        if api_path == "/searchautomations":
            status, body = _handle_search_automations(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/describeautomation", "/getautomation"):
            status, body = _handle_describe_automation(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/automationsummary", "/getautomationsummary"):
            status, body = _handle_automation_summary(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path == "/searchqueryactivities":
            status, body = _handle_search_queries(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/describequeryactivity", "/getqueryactivity"):
            status, body = _handle_describe_query(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path == "/searchimportactivities":
            status, body = _handle_search_imports(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/describeimportactivity", "/getimportactivity"):
            status, body = _handle_describe_import(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        return _bedrock_actiongroup_response(event, {"ok": False, "error": f"Unknown apiPath: {api_path}"}, http_code=400)

    # Direct invoke (API Gateway-style)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event).lower()

    if path == "/searchautomations":
        status, body = _handle_search_automations(params)
        return _json_response(body, status)

    if path in ("/describeautomation", "/getautomation"):
        status, body = _handle_describe_automation(params)
        return _json_response(body, status)

    if path in ("/automationsummary", "/getautomationsummary"):
        status, body = _handle_automation_summary(params)
        return _json_response(body, status)

    if path == "/searchqueryactivities":
        status, body = _handle_search_queries(params)
        return _json_response(body, status)

    if path in ("/describequeryactivity", "/getqueryactivity"):
        status, body = _handle_describe_query(params)
        return _json_response(body, status)

    if path == "/searchimportactivities":
        status, body = _handle_search_imports(params)
        return _json_response(body, status)

    if path in ("/describeimportactivity", "/getimportactivity"):
        status, body = _handle_describe_import(params)
        return _json_response(body, status)

    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
