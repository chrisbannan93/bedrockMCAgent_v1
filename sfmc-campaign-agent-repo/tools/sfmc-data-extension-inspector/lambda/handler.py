import os
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote
import xml.etree.ElementTree as ET

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Guardrails (hard caps)
# -----------------------------
MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "50"))                 # hard cap for paging
MAX_SAMPLE_ROWS = int(os.getenv("DE_SAMPLE_MAX_ROWS", "20"))          # hard cap for sample rows
DE_SEARCH_MAX_ITEMS = int(os.getenv("DE_SEARCH_MAX_ITEMS", "200"))    # hard cap for SOAP DE search
DATAFOLDER_SEARCH_MAX_ITEMS = int(os.getenv("DATAFOLDER_SEARCH_MAX_ITEMS", "300"))
DATAFOLDER_INCLUDE_PATH_CAP = int(os.getenv("DATAFOLDER_INCLUDE_PATH_CAP", "10"))
SOAP_TIMEOUT = int(os.getenv("SOAP_TIMEOUT", "30"))
REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "30"))

# Sample-row safety (PII masking + truncation)
DE_SAMPLE_MASK_PII_DEFAULT = str(os.getenv("DE_SAMPLE_MASK_PII", "true")).lower() == "true"
DE_SAMPLE_TRUNCATE_LEN = int(os.getenv("DE_SAMPLE_TRUNCATE_LEN", "200"))

# Optional: enforce we only run for a specific account_id (BU) if you set it
# e.g. SFMC_ALLOWED_ACCOUNT_ID="123456789"
SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
    "soap_base_url": None,
}

# Folder caches (warm Lambda reuse)
_FOLDER_META_CACHE: Dict[int, dict] = {}   # folderId -> {ID, Name, ParentFolder.ID, ...}
_FOLDER_PATH_CACHE: Dict[int, dict] = {}   # folderId -> {folderId, pathSegments, path, maxDepthReached}

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
                "application/json": {"body": json.dumps(body_obj)}
            },
        },
    }


def _is_bedrock_event(event: dict) -> bool:
    return "messageVersion" in event and "response" not in event


def _http_json(
    method: str,
    url: str,
    headers: dict,
    payload: Optional[dict] = None,
    timeout: int = REST_TIMEOUT,
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


def _http_soap(url: str, soap_xml: str, timeout: int = SOAP_TIMEOUT) -> Tuple[int, str]:
    # SFMC Partner SOAP is SOAP 1.1.
    # Some tenants (or some objects like DataFolder) reject without SOAPAction.
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "Retrieve",   # ✅ FIX: no embedded quotes
        "Accept": "text/xml",
    }
    data = soap_xml.encode("utf-8")
    req = Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, raw
    except HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, raw or str(e)
    except URLError as e:
        return 599, f"URLError: {e}"


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

        if "<item>" in s and "</item>" in s:
            items = re.findall(r"<item>(.*?)</item>", s)
            return [i.strip() for i in items if i.strip()]

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

    # Bedrock sometimes wraps properties
    if isinstance(aj, dict):
        props = aj.get("properties")
        if isinstance(props, list):
            for it in props:
                name = it.get("name")
                if not name:
                    continue
                out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            return out

    if isinstance(aj, list):
        for it in aj:
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
        return out

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


# -----------------------------
# Helpers: Secrets + SFMC Auth
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


def _derive_soap_from_auth(auth_base: str) -> str:
    soap = auth_base.replace(".auth.", ".soap.")
    return _norm_base(soap)


def _ensure_service_asmx(url: str) -> str:
    u = _norm_base(url)
    if not u:
        return u
    return u if u.lower().endswith("/service.asmx") else (u + "/Service.asmx")


def _get_sfmc_bases(secret: dict) -> Tuple[str, str, str]:
    auth_base = _norm_base(
        os.getenv("SFMC_AUTH_BASE_URL", "")
        or os.getenv("auth_url", "")
        or secret.get("auth_base_url", "")
        or secret.get("auth_url", "")
    )
    if not auth_base:
        raise ValueError("Missing auth base URL (set auth_url or SFMC_AUTH_BASE_URL or secret.auth_base_url)")

    rest_base = _norm_base(
        os.getenv("SFMC_REST_BASE_URL", "")
        or secret.get("rest_base_url", "")
        or secret.get("rest_url", "")
    ) or _derive_rest_from_auth(auth_base)

    soap_base_raw = _norm_base(
        os.getenv("SFMC_SOAP_BASE_URL", "")
        or secret.get("soap_base_url", "")
        or secret.get("soap_url", "")
    ) or _derive_soap_from_auth(auth_base)

    soap_base = _ensure_service_asmx(soap_base_raw)

    return auth_base, rest_base, soap_base


def _enforce_account_guardrail(secret: dict) -> None:
    if not SFMC_ALLOWED_ACCOUNT_ID:
        return
    acct = str(secret.get("account_id") or secret.get("accountId") or "").strip()
    if not acct:
        raise ValueError("Guardrail: SFMC_ALLOWED_ACCOUNT_ID is set but secret has no account_id/accountId")
    if acct != SFMC_ALLOWED_ACCOUNT_ID:
        raise ValueError(f"Guardrail: account_id {acct} not allowed (expected {SFMC_ALLOWED_ACCOUNT_ID})")


def _get_access_token() -> Tuple[str, str, str]:
    now = int(time.time())
    if _TOKEN_CACHE["access_token"] and now < int(_TOKEN_CACHE["expires_at"] or 0) - 30:
        return _TOKEN_CACHE["access_token"], _TOKEN_CACHE["rest_base_url"], _TOKEN_CACHE["soap_base_url"]

    secret = _load_secret_json()
    _enforce_account_guardrail(secret)

    client_id = secret.get("client_id") or secret.get("clientId")
    client_secret = secret.get("client_secret") or secret.get("clientSecret")
    account_id = secret.get("account_id") or secret.get("accountId")  # optional BU scoping

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

    status, body = _http_json("POST", token_url, headers={}, payload=payload)
    if status < 200 or status >= 300:
        raise RuntimeError(f"SFMC auth failed ({status}): {body}")

    access_token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 1200)
    if not access_token:
        raise RuntimeError(f"SFMC auth missing access_token: {body}")

    # ✅ FIX: Use instance URLs from token response when available (most reliable)
    token_rest = body.get("rest_instance_url") or body.get("restInstanceUrl")
    token_soap = body.get("soap_instance_url") or body.get("soapInstanceUrl")
    if token_rest:
        rest_base = _norm_base(token_rest)
    if token_soap:
        soap_base = _ensure_service_asmx(_norm_base(token_soap))

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base
    _TOKEN_CACHE["soap_base_url"] = soap_base

    return access_token, rest_base, soap_base


def _sfmc_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


# -----------------------------
# SOAP: Retrieve helpers
# -----------------------------
SOAPENV_NS_11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAPENV_NS_12 = "http://www.w3.org/2003/05/soap-envelope"
PARTNER_NS = "http://exacttarget.com/wsdl/partnerAPI"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"


def _local(tag: str) -> str:
    if not tag:
        return ""
    return tag.split("}", 1)[-1] if "}" in tag else tag


# ✅ FIX: don't put the PartnerAPI namespace as the default on the Envelope
# (it can cause <fueloauth> to be namespaced and rejected by SFMC in some stacks)
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


# ✅ FIX: declare PartnerAPI namespace on the RetrieveRequestMsg element instead
def _soap_retrieve_request_xml(
    object_type: str,
    properties: List[str],
    filter_xml: Optional[str] = None,
    continue_request_id: Optional[str] = None,
) -> str:
    props_xml = "\n".join([f"<Properties>{p}</Properties>" for p in properties])

    if continue_request_id:
        return f"""
<RetrieveRequestMsg xmlns="{PARTNER_NS}">
  <RetrieveRequest>
    <ContinueRequest>{continue_request_id}</ContinueRequest>
  </RetrieveRequest>
</RetrieveRequestMsg>
"""

    fxml = filter_xml or ""
    return f"""
<RetrieveRequestMsg xmlns="{PARTNER_NS}">
  <RetrieveRequest>
    <ObjectType>{object_type}</ObjectType>
    {props_xml}
    {fxml}
  </RetrieveRequest>
</RetrieveRequestMsg>
"""


def _soap_simple_filter(property_name: str, operator: str, value: str) -> str:
    return f"""
<Filter xsi:type="SimpleFilterPart">
  <Property>{property_name}</Property>
  <SimpleOperator>{operator}</SimpleOperator>
  <Value>{value}</Value>
</Filter>
"""


def _find_soap_body(root: ET.Element) -> Optional[ET.Element]:
    body = root.find(f".//{{{SOAPENV_NS_11}}}Body")
    if body is not None:
        return body
    return root.find(f".//{{{SOAPENV_NS_12}}}Body")


def _soap_fault_summary(xml_text: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    body = _find_soap_body(root)
    if body is None:
        return None

    fault = None
    for el in body.iter():
        if _local(el.tag) == "Fault":
            fault = el
            break
    if fault is None:
        return None

    # SOAP 1.1
    faultcode = None
    faultstring = None

    for ch in list(fault):
        nm = _local(ch.tag)
        if nm == "faultcode":
            faultcode = (ch.text or "").strip()
        elif nm == "faultstring":
            faultstring = (ch.text or "").strip()

    if faultstring or faultcode:
        return f"{faultcode or ''} {faultstring or ''}".strip()

    # SOAP 1.2
    code_val = None
    reason_text = None
    for el in fault.iter():
        if _local(el.tag) == "Value" and code_val is None:
            code_val = (el.text or "").strip()
        if _local(el.tag) == "Text" and reason_text is None:
            reason_text = (el.text or "").strip()

    if code_val or reason_text:
        return f"{code_val or ''} {reason_text or ''}".strip()

    return "SOAP Fault returned (could not parse details)"


def _parse_retrieve_response(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)

    body = _find_soap_body(root)
    if body is None:
        return {"request_id": "", "more_data": False, "overall_status": None, "status_message": None, "results": []}

    rrm = None
    for el in body.iter():
        if _local(el.tag) == "RetrieveResponseMsg":
            rrm = el
            break

    if rrm is None:
        return {"request_id": "", "more_data": False, "overall_status": None, "status_message": None, "results": []}

    request_id = ""
    more_data = False
    overall_status = None
    status_message = None
    results: List[dict] = []

    for child in list(rrm):
        name = _local(child.tag)
        if name == "RequestID":
            request_id = (child.text or "").strip()
        elif name == "MoreDataAvailable":
            more_data = (child.text or "").strip().lower() == "true"
        elif name == "OverallStatus":
            overall_status = (child.text or "").strip()
        elif name == "StatusMessage":
            status_message = (child.text or "").strip()
        elif name == "Results":
            row = {}
            for leaf in list(child):
                if list(leaf):
                    nested_obj = {}
                    for sub in list(leaf):
                        nested_obj[_local(sub.tag)] = (sub.text or "").strip()
                    row[_local(leaf.tag)] = nested_obj
                else:
                    row[_local(leaf.tag)] = (leaf.text or "").strip()
            results.append(row)

    return {
        "request_id": request_id,
        "more_data": more_data,
        "overall_status": overall_status,
        "status_message": status_message,
        "results": results,
    }


def _soap_retrieve_all(
    fueloauth: str,
    soap_base: str,
    object_type: str,
    properties: List[str],
    filter_xml: Optional[str] = None,
    max_items: int = 200,
) -> List[dict]:
    items: List[dict] = []
    debug_soap = str(os.getenv("DEBUG_SOAP", "false")).lower() == "true"
    trunc = int(os.getenv("DEBUG_SOAP_TRUNCATE", "1200"))

    body_xml = _soap_retrieve_request_xml(object_type, properties, filter_xml=filter_xml)
    env = _soap_envelope(fueloauth, body_xml)

    status, resp_xml = _http_soap(soap_base, env)
    if status < 200 or status >= 300:
        fault_msg = _soap_fault_summary(resp_xml)
        raise RuntimeError(f"SOAP retrieve failed ({status}) for {object_type}: {fault_msg or resp_xml[:500]}")

    parsed = _parse_retrieve_response(resp_xml)

    if debug_soap:
        logger.info("SOAP %s OverallStatus=%s StatusMessage=%s", object_type, parsed.get("overall_status"), parsed.get("status_message"))
        logger.info("SOAP %s response (trunc): %s", object_type, resp_xml[:trunc])

    overall = (parsed.get("overall_status") or "").lower()
    if overall and not overall.startswith("ok"):
        raise RuntimeError(f"SOAP Retrieve {object_type} OverallStatus={parsed.get('overall_status')} StatusMessage={parsed.get('status_message')}")

    req_id = parsed.get("request_id") or ""
    more = bool(parsed.get("more_data"))
    batch = parsed.get("results") or []
    items.extend(batch)

    while more and req_id and len(items) < max_items:
        body_xml = _soap_retrieve_request_xml(object_type, properties, continue_request_id=req_id)
        env = _soap_envelope(fueloauth, body_xml)

        status, resp_xml = _http_soap(soap_base, env)
        if status < 200 or status >= 300:
            fault_msg = _soap_fault_summary(resp_xml)
            raise RuntimeError(f"SOAP continue retrieve failed ({status}) for {object_type}: {fault_msg or resp_xml[:500]}")

        parsed = _parse_retrieve_response(resp_xml)

        overall = (parsed.get("overall_status") or "").lower()
        if overall and not overall.startswith("ok"):
            raise RuntimeError(f"SOAP Continue Retrieve {object_type} OverallStatus={parsed.get('overall_status')} StatusMessage={parsed.get('status_message')}")

        req_id = parsed.get("request_id") or ""
        more = bool(parsed.get("more_data"))
        batch = parsed.get("results") or []
        items.extend(batch)

    return items[:max_items]


def _soap_retrieve_all_with_fallback(
    fueloauth: str,
    soap_base: str,
    object_type: str,
    properties_primary: List[str],
    properties_fallback: List[str],
    filter_xml: Optional[str] = None,
    max_items: int = 200,
) -> Tuple[List[dict], bool]:
    try:
        rows = _soap_retrieve_all(
            fueloauth=fueloauth,
            soap_base=soap_base,
            object_type=object_type,
            properties=properties_primary,
            filter_xml=filter_xml,
            max_items=max_items,
        )
        return rows, False
    except Exception as e:
        logger.warning("SOAP %s retrieve failed with primary props. Falling back. Error=%s", object_type, str(e))
        rows = _soap_retrieve_all(
            fueloauth=fueloauth,
            soap_base=soap_base,
            object_type=object_type,
            properties=properties_fallback,
            filter_xml=filter_xml,
            max_items=max_items,
        )
        return rows, True


# -----------------------------
# Data Extension Inspector
# -----------------------------
def _op_to_like(name_operator: Optional[str], text: str) -> Tuple[str, str]:
    op = (name_operator or "").strip().lower()
    if op in ("equals", "eq"):
        return "equals", text
    if op in ("startswith", "starts_with", "starts"):
        return "like", f"{text}%"
    return "like", f"%{text}%"


def search_data_extensions(
    query_text: Optional[str],
    name_operator: Optional[str],
    customer_key: Optional[str],
    page: int,
    page_size: int,
    fields: Optional[List[str]],
) -> dict:
    access_token, rest_base, soap_base = _get_access_token()

    max_items = DE_SEARCH_MAX_ITEMS
    page = _clamp_page(page)
    page_size = _clamp_page_size(page_size, cap=MAX_PAGE_SIZE, default=25)

    props = [
        "Name",
        "CustomerKey",
        "ObjectID",
        "CategoryID",
        "IsSendable",
        "Description",
        "CreatedDate",
        "ModifiedDate",
    ]

    filter_xml = None
    if customer_key:
        filter_xml = _soap_simple_filter("CustomerKey", "equals", str(customer_key))
    elif query_text:
        op, val = _op_to_like(name_operator, str(query_text))
        filter_xml = _soap_simple_filter("Name", op, val)

    if not customer_key and not query_text:
        raise ValueError("Provide queryText or customerKey")

    rows = _soap_retrieve_all(
        fueloauth=access_token,
        soap_base=soap_base,
        object_type="DataExtension",
        properties=props,
        filter_xml=filter_xml,
        max_items=max_items,
    )

    total = len(rows)
    start = (page - 1) * page_size
    end = start + page_size
    slice_rows = rows[start:end] if start < total else []

    def norm_item(r: dict) -> dict:
        return {
            "name": r.get("Name"),
            "customerKey": r.get("CustomerKey"),
            "objectId": r.get("ObjectID"),
            "categoryId": int(r["CategoryID"]) if r.get("CategoryID") and str(r.get("CategoryID")).isdigit() else r.get("CategoryID"),
            "isSendable": (r.get("IsSendable") or "").lower() == "true" if r.get("IsSendable") is not None else None,
            "description": r.get("Description"),
            "createdDate": r.get("CreatedDate"),
            "modifiedDate": r.get("ModifiedDate"),
        }

    items = [norm_item(r) for r in slice_rows]

    if fields:
        fset = set([str(x) for x in fields])
        items = [{k: v for k, v in it.items() if k in fset} for it in items]

    return {"count": total, "page": page, "pageSize": page_size, "items": items}


def _get_datafolder_path(access_token: str, soap_base: str, folder_id: int, max_depth: int = 50) -> dict:
    # Cache hit?
    fid = int(folder_id)
    if fid in _FOLDER_PATH_CACHE:
        return _FOLDER_PATH_CACHE[fid]

    primary_props = ["ID", "Name", "ParentFolder.ID"]
    # ✅ FIX: include ParentFolder in fallback so we still have a parent pointer
    fallback_props = ["ID", "Name", "ParentFolder"]

    def retrieve_folder(fid_inner: int) -> Optional[dict]:
        fid_inner = int(fid_inner)

        if fid_inner in _FOLDER_META_CACHE:
            return _FOLDER_META_CACHE[fid_inner]

        fxml = _soap_simple_filter("ID", "equals", str(fid_inner))
        rows, _ = _soap_retrieve_all_with_fallback(
            fueloauth=access_token,
            soap_base=soap_base,
            object_type="DataFolder",
            properties_primary=primary_props,
            properties_fallback=fallback_props,
            filter_xml=fxml,
            max_items=5,
        )
        row = rows[0] if rows else None
        if row:
            _FOLDER_META_CACHE[fid_inner] = row
        return row

    segments: List[str] = []
    cur = fid
    depth = 0
    max_depth_reached = False

    while cur and depth < max_depth:
        depth += 1
        row = retrieve_folder(cur)
        if not row:
            break

        name = row.get("Name")
        if name:
            segments.append(name)

        parent = None
        if isinstance(row.get("ParentFolder"), dict):
            parent = row["ParentFolder"].get("ID")
        if not parent:
            parent = row.get("ParentFolder.ID")

        try:
            cur = int(parent) if parent else 0
        except Exception:
            cur = 0

    if depth >= max_depth:
        max_depth_reached = True

    segments.reverse()
    out = {
        "folderId": fid,
        "pathSegments": segments,
        "path": "/".join(segments) if segments else None,
        "maxDepthReached": max_depth_reached,
    }
    _FOLDER_PATH_CACHE[fid] = out
    return out


def _retrieve_de_fields(access_token: str, soap_base: str, customer_key: str, object_id: str) -> List[dict]:
    field_props = [
        "Name",
        "FieldType",
        "MaxLength",
        "IsPrimaryKey",
        "IsRequired",
        "Ordinal",
        "DefaultValue",
    ]

    filters_to_try = [
        _soap_simple_filter("DataExtension.CustomerKey", "equals", str(customer_key)),
        _soap_simple_filter("DataExtension.ObjectID", "equals", str(object_id)),
    ]

    last_err = None
    for fxml in filters_to_try:
        try:
            rows = _soap_retrieve_all(
                fueloauth=access_token,
                soap_base=soap_base,
                object_type="DataExtensionField",
                properties=field_props,
                filter_xml=fxml,
                max_items=2000,
            )
            if rows:
                return rows
        except Exception as e:
            last_err = e

    if last_err:
        raise last_err
    return []


def describe_data_extension(
    customer_key: Optional[str],
    object_id: Optional[str],
    include_folder_path: bool,
    include_fields: bool = True,
) -> dict:
    access_token, rest_base, soap_base = _get_access_token()

    if not customer_key and not object_id:
        raise ValueError("Provide customerKey or objectId")

    de_props = [
        "Name",
        "CustomerKey",
        "ObjectID",
        "CategoryID",
        "IsSendable",
        "Description",
        "CreatedDate",
        "ModifiedDate",
    ]

    if customer_key:
        filter_xml = _soap_simple_filter("CustomerKey", "equals", str(customer_key))
    else:
        filter_xml = _soap_simple_filter("ObjectID", "equals", str(object_id))

    des = _soap_retrieve_all(
        fueloauth=access_token,
        soap_base=soap_base,
        object_type="DataExtension",
        properties=de_props,
        filter_xml=filter_xml,
        max_items=5,
    )
    if not des:
        raise FileNotFoundError("Data Extension not found for provided identifier")

    de = des[0]
    resolved_key = de.get("CustomerKey") or ""
    resolved_object_id = de.get("ObjectID") or ""

    fields = []
    if include_fields:
        fields = _retrieve_de_fields(access_token, soap_base, resolved_key, resolved_object_id)

    def _bool(v):
        if v is None:
            return None
        return str(v).strip().lower() == "true"

    def _int(v):
        try:
            return int(v)
        except Exception:
            return None

    def norm_field(r: dict) -> dict:
        return {
            "name": r.get("Name"),
            "fieldType": r.get("FieldType"),
            "maxLength": _int(r.get("MaxLength")),
            "ordinal": _int(r.get("Ordinal")),
            "isPrimaryKey": _bool(r.get("IsPrimaryKey")),
            "isRequired": _bool(r.get("IsRequired")),
            "defaultValue": r.get("DefaultValue"),
        }

    try:
        cat_id = int(de.get("CategoryID")) if de.get("CategoryID") else None
    except Exception:
        cat_id = None

    folder_info = None
    if include_folder_path and cat_id is not None:
        try:
            folder_info = _get_datafolder_path(access_token, soap_base, cat_id)
        except Exception as e:
            folder_info = {"error": str(e)}

    warnings = []
    if include_fields and len(fields) == 0:
        warnings.append(
            "No DataExtensionField results returned. If this DE definitely has fields in the UI, "
            "enable DEBUG_SOAP=true and re-run to see SOAP OverallStatus/StatusMessage. "
            "This can also be a permission issue for DataExtensionField retrieve."
        )

    out = {
        "dataExtension": {
            "name": de.get("Name"),
            "customerKey": de.get("CustomerKey"),
            "objectId": de.get("ObjectID"),
            "categoryId": cat_id,
            "isSendable": (de.get("IsSendable") or "").lower() == "true" if de.get("IsSendable") is not None else None,
            "description": de.get("Description"),
            "createdDate": de.get("CreatedDate"),
            "modifiedDate": de.get("ModifiedDate"),
        },
        "fields": [norm_field(f) for f in fields],
        "folder": folder_info,
        "warnings": warnings,
    }
    return out


# -----------------------------
# Sample rows (REST Data API)
# -----------------------------
_SENSITIVE_FIELD_RE = re.compile(
    r"(email|e-?mail|phone|mobile|msisdn|address|dob|birth|first_?name|last_?name|full_?name|postcode|zip|iban|bsb|account|credit|card)",
    re.IGNORECASE
)


def _truncate_str(s: Any, max_len: int) -> Any:
    if s is None:
        return None
    if not isinstance(s, str):
        return s
    return s if len(s) <= max_len else (s[:max_len] + "…")


def _mask_value(field_name: str, value: Any) -> Any:
    if value is None:
        return None

    name = (field_name or "")
    if not _SENSITIVE_FIELD_RE.search(name):
        return _truncate_str(value, DE_SAMPLE_TRUNCATE_LEN)

    s = str(value)

    # email-like
    if "email" in name.lower() and "@" in s:
        local, _, domain = s.partition("@")
        local_masked = (local[:1] + "***") if local else "***"
        return _truncate_str(f"{local_masked}@{domain}", DE_SAMPLE_TRUNCATE_LEN)

    # phone-like
    if any(x in name.lower() for x in ["phone", "mobile", "msisdn"]):
        digits = re.sub(r"\D", "", s)
        if len(digits) >= 3:
            return f"***{digits[-3:]}"
        return "***"

    return "REDACTED"


def _sanitize_row_item(item: Any, columns: Optional[List[str]], mask_pii: bool) -> Any:
    if not isinstance(item, dict):
        return item

    cset = set([str(c) for c in columns]) if columns else None

    def _filter_dict(d: Any) -> Any:
        if not isinstance(d, dict):
            return d
        out = {}
        for k, v in d.items():
            if cset is not None and str(k) not in cset:
                continue
            out[str(k)] = _mask_value(str(k), v) if mask_pii else _truncate_str(v, DE_SAMPLE_TRUNCATE_LEN)
        return out

    # Typical rowset format: { keys: {...}, values: {...} }
    if "keys" in item or "values" in item:
        base = {k: v for k, v in item.items() if k not in ("keys", "values")}
        base["keys"] = _filter_dict(item.get("keys"))
        base["values"] = _filter_dict(item.get("values"))
        return base

    # Fallback: plain dict row
    return _filter_dict(item)


def sample_data_extension_rows(
    customer_key: str,
    page_size: int = 10,
    columns: Optional[List[str]] = None,
    mask_pii: Optional[bool] = None,
) -> dict:
    access_token, rest_base, soap_base = _get_access_token()
    headers = _sfmc_headers(access_token)

    page_size = _clamp_page_size(page_size, cap=MAX_SAMPLE_ROWS, default=10)
    mask = DE_SAMPLE_MASK_PII_DEFAULT if mask_pii is None else bool(mask_pii)

    ck_enc = quote(str(customer_key), safe="")

    # Prefer canonical casing: $pageSize
    url_primary = f"{rest_base}/data/v1/customobjectdata/key/{ck_enc}/rowset?$pageSize={page_size}"
    status, body = _http_json("GET", url_primary, headers=headers, payload=None)

    # Fallback for tenants that accept $pagesize
    if status < 200 or status >= 300:
        url_fallback = f"{rest_base}/data/v1/customobjectdata/key/{ck_enc}/rowset?$pagesize={page_size}"
        status2, body2 = _http_json("GET", url_fallback, headers=headers, payload=None)
        if 200 <= status2 < 300:
            status, body = status2, body2

    if status < 200 or status >= 300:
        raise RuntimeError(f"Sample rows failed ({status}): {body}")

    items = body.get("items") or body.get("rows") or body.get("Results") or []
    if not isinstance(items, list):
        items = []

    sanitized = [_sanitize_row_item(row, columns=columns, mask_pii=mask) for row in items]
    return {"pageSize": page_size, "items": sanitized}


# -----------------------------
# DataFolder search / list
# -----------------------------
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


def search_data_folders(
    query_text: Optional[str],
    name_operator: Optional[str],
    parent_id: Optional[int],
    content_types: Optional[Union[str, List[str]]],
    page: int,
    page_size: int,
    include_path: bool,
) -> dict:
    access_token, rest_base, soap_base = _get_access_token()

    max_items = DATAFOLDER_SEARCH_MAX_ITEMS
    page = _clamp_page(page)
    page_size = _clamp_page_size(page_size, cap=MAX_PAGE_SIZE, default=25)

    if query_text is None and parent_id is None:
        raise ValueError("Provide queryText or parentId")

    primary_props = ["ID", "Name", "ParentFolder.ID", "ContentType", "Description"]
    # ✅ FIX: include ParentFolder in fallback for parent pointer support
    fallback_props = ["ID", "Name", "ParentFolder.ID", "ParentFolder"]

    filter_xml = None
    if parent_id is not None:
        filter_xml = _soap_simple_filter("ParentFolder.ID", "equals", str(int(parent_id)))
    elif query_text:
        op, val = _op_to_like(name_operator, str(query_text))
        filter_xml = _soap_simple_filter("Name", op, val)

    rows, used_fallback = _soap_retrieve_all_with_fallback(
        fueloauth=access_token,
        soap_base=soap_base,
        object_type="DataFolder",
        properties_primary=primary_props,
        properties_fallback=fallback_props,
        filter_xml=filter_xml,
        max_items=max_items,
    )

    filtered = rows

    if parent_id is not None and query_text:
        filtered = [r for r in filtered if _name_matches(r.get("Name", ""), str(query_text), name_operator or "contains")]

    if content_types:
        if isinstance(content_types, str):
            ct_set = {content_types.strip().lower()}
        else:
            ct_set = {str(x).strip().lower() for x in content_types if str(x).strip()}
        filtered = [r for r in filtered if (r.get("ContentType") or "").strip().lower() in ct_set]

    total = len(filtered)
    start = (page - 1) * page_size
    end = start + page_size
    slice_rows = filtered[start:end] if start < total else []

    def _to_int(v):
        try:
            return int(v)
        except Exception:
            return None

    items = []
    warnings = []
    do_paths = bool(include_path)

    if do_paths and page_size > DATAFOLDER_INCLUDE_PATH_CAP:
        warnings.append(f"includePath is enabled, but paths will only be computed for the first {DATAFOLDER_INCLUDE_PATH_CAP} items (cap).")

    for i, r in enumerate(slice_rows):
        parent_val = None
        if r.get("ParentFolder.ID"):
            parent_val = r.get("ParentFolder.ID")
        elif isinstance(r.get("ParentFolder"), dict):
            parent_val = (r.get("ParentFolder") or {}).get("ID")

        item = {
            "id": _to_int(r.get("ID")),
            "name": r.get("Name"),
            "description": r.get("Description"),
            "contentType": r.get("ContentType"),
            "parentId": _to_int(parent_val),
        }

        if do_paths and item["id"] is not None and i < DATAFOLDER_INCLUDE_PATH_CAP:
            try:
                item["path"] = _get_datafolder_path(access_token, soap_base, int(item["id"])).get("path")
            except Exception:
                item["path"] = None

        items.append(item)

    if used_fallback:
        warnings.append("DataFolder retrieve required fallback property set (tenant/BU may not support ContentType/Description on retrieve).")

    return {"count": total, "page": page, "pageSize": page_size, "items": items, "warnings": warnings}


def describe_data_folder_path(folder_id: int, max_depth: int = 50) -> dict:
    access_token, rest_base, soap_base = _get_access_token()
    if folder_id is None:
        raise ValueError("folderId is required")
    md = int(max_depth) if max_depth else 50
    if md < 1:
        md = 1
    if md > 100:
        md = 100  # guardrail
    return _get_datafolder_path(access_token, soap_base, int(folder_id), max_depth=md)


# -----------------------------
# Tool handlers
# -----------------------------
def _handle_search_des(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        output = search_data_extensions(
            query_text=params.get("queryText"),
            name_operator=params.get("nameOperator"),
            customer_key=params.get("customerKey"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
            fields=params.get("fields") if isinstance(params.get("fields"), list) else None,
        )
        return 200, {"ok": True, "tool": "data_extension_search", "input": params, "output": output, "warnings": []}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("searchDataExtensions failed")
        return 500, {"ok": False, "error": str(e)}


def _handle_describe_de(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        include_folder = params.get("includeFolderPath", True)
        include_fields = params.get("includeFields", True)

        output = describe_data_extension(
            customer_key=params.get("customerKey"),
            object_id=params.get("objectId"),
            include_folder_path=bool(include_folder),
            include_fields=bool(include_fields),
        )
        return 200, {
            "ok": True,
            "tool": "data_extension_describe",
            "input": params,
            "output": output,
            "warnings": output.get("warnings", []),
        }
    except FileNotFoundError as e:
        return 404, {"ok": False, "error": str(e)}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("describeDataExtension failed")
        return 500, {"ok": False, "error": str(e)}


def _handle_sample_rows(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        ck = params.get("customerKey")
        if not ck:
            return 400, {"ok": False, "error": "customerKey is required"}

        output = sample_data_extension_rows(
            customer_key=str(ck),
            page_size=int(params.get("pageSize") or 10),
            columns=params.get("columns") if isinstance(params.get("columns"), list) else None,
            mask_pii=params.get("maskPII"),
        )
        return 200, {"ok": True, "tool": "data_extension_sample_rows", "input": params, "output": output, "warnings": []}
    except Exception as e:
        logger.exception("sampleDataExtensionRows failed")
        return 500, {"ok": False, "error": str(e)}


def _handle_search_folders(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        parent_id = params.get("parentId")
        parent_id_int = int(parent_id) if parent_id is not None else None

        output = search_data_folders(
            query_text=params.get("queryText"),
            name_operator=params.get("nameOperator"),
            parent_id=parent_id_int,
            content_types=params.get("contentTypes") or params.get("contentType"),
            page=int(params.get("page") or 1),
            page_size=int(params.get("pageSize") or 25),
            include_path=bool(params.get("includePath") or False),
        )
        return 200, {"ok": True, "tool": "data_folder_search", "input": params, "output": output, "warnings": output.get("warnings", [])}
    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("searchDataFolders failed")
        return 500, {"ok": False, "error": str(e)}


def _handle_folder_path(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        fid = params.get("folderId") or params.get("id")
        if fid is None:
            return 400, {"ok": False, "error": "folderId is required"}

        # --- Clamp maxDepth early so the response echo matches the effective behavior ---
        requested_raw = params.get("maxDepth", None)

        try:
            requested = int(requested_raw) if requested_raw is not None else 50
        except Exception:
            requested = 50

        effective = requested
        if effective < 1:
            effective = 1
        if effective > 100:
            effective = 100

        # Build a clean input echo:
        input_echo = dict(params)  # shallow copy
        input_echo["folderId"] = int(fid)  # normalize
        input_echo["maxDepthRequested"] = requested
        input_echo["maxDepth"] = effective  # effective (clamped) value

        warnings = []
        if requested != effective:
            warnings.append(f"maxDepth was clamped from {requested} to {effective} (guardrail).")

        output = describe_data_folder_path(
            folder_id=int(fid),
            max_depth=effective,  # IMPORTANT: use the clamped value
        )

        return 200, {
            "ok": True,
            "tool": "data_folder_path",
            "input": input_echo,
            "output": output,
            "warnings": warnings,
        }

    except ValueError as e:
        return 400, {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("describeDataFolderPath failed")
        return 500, {"ok": False, "error": str(e)}


# -----------------------------
# Lambda entrypoint
# -----------------------------
def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list(event.keys()))

    # Bedrock
    if _is_bedrock_event(event):
        api_path = _get_api_path(event)
        params = _parse_bedrock_params(event)

        logger.info("Bedrock apiPath=%s httpMethod=%s", api_path, _get_http_method(event))
        logger.info("Parsed Bedrock params: %s", params)

        p = api_path.lower()

        if p == "/searchdataextensions":
            status, body = _handle_search_des(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        # Accept aliases (schema drift-proof)
        if p in ("/describedataextension", "/getdataextension", "/inspectdataextension"):
            status, body = _handle_describe_de(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if p == "/sampledataextensionrows":
            status, body = _handle_sample_rows(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        # Folders
        if p == "/searchdatafolders":
            status, body = _handle_search_folders(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if p in ("/describedatafolderpath", "/getdatafolderpath"):
            status, body = _handle_folder_path(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        body = {"ok": False, "error": f"Unknown apiPath: {api_path}"}
        return _bedrock_actiongroup_response(event, body, http_code=400)

    # Direct invoke (API Gateway-style)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event).lower()

    if path == "/searchdataextensions":
        status, body = _handle_search_des(params)
        return _json_response(body, status)

    if path in ("/describedataextension", "/getdataextension", "/inspectdataextension"):
        status, body = _handle_describe_de(params)
        return _json_response(body, status)

    if path == "/sampledataextensionrows":
        status, body = _handle_sample_rows(params)
        return _json_response(body, status)

    if path == "/searchdatafolders":
        status, body = _handle_search_folders(params)
        return _json_response(body, status)

    if path in ("/describedatafolderpath", "/getdatafolderpath"):
        status, body = _handle_folder_path(params)
        return _json_response(body, status)

    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
