import os
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote
import xml.etree.ElementTree as ET

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")

# -----------------------------
# Guardrails / Limits
# -----------------------------
REST_TIMEOUT = int(os.getenv("REST_TIMEOUT", "30"))

MAX_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", "50"))
SEARCH_MAX_ITEMS = int(os.getenv("SEARCH_MAX_ITEMS", "200"))

MAX_FIELDS = int(os.getenv("MAX_FIELDS", "60"))
MAX_FIELD_NAME_LEN = int(os.getenv("MAX_FIELD_NAME_LEN", "100"))
MAX_DE_NAME_LEN = int(os.getenv("MAX_DE_NAME_LEN", "200"))
MAX_CUSTOMER_KEY_LEN = int(os.getenv("MAX_CUSTOMER_KEY_LEN", "128"))

DEFAULT_DRY_RUN = str(os.getenv("DEFAULT_DRY_RUN", "true")).strip().lower() in ("true", "1", "yes", "y")
ALLOW_CREATE_MISSING_FOLDERS_DEFAULT = str(os.getenv("ALLOW_CREATE_MISSING_FOLDERS_DEFAULT", "false")).strip().lower() in ("true", "1", "yes", "y")
DATAEXT_ROOT_FOLDER_ID = str(os.getenv("DATAEXT_ROOT_FOLDER_ID", "0")).strip()  # SOAP DataFolder root to start traversal
DATAEXT_FOLDER_CONTENT_TYPE = str(os.getenv("DATAEXT_FOLDER_CONTENT_TYPE", "dataextension")).strip()

SAFE_DATAEXT_FOLDER_ROOT = (os.getenv("SAFE_DATAEXT_FOLDER_ROOT") or "").strip()
SFMC_ALLOWED_ACCOUNT_ID = (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()

# If you want a hard "sandbox only" flag beyond account allowlist:
REQUIRE_SANDBOX_FLAG = str(os.getenv("REQUIRE_SANDBOX_FLAG", "false")).strip().lower() in ("true", "1", "yes", "y")
SFMC_ENVIRONMENT = (os.getenv("SFMC_ENVIRONMENT") or "").strip().lower()  # e.g., "sandbox"

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# -----------------------------
# Token cache (warm Lambda reuse)
# -----------------------------
_TOKEN_CACHE = {
    "access_token": None,
    "expires_at": 0,
    "rest_base_url": None,
    "soap_base_url": None,
}

# -----------------------------
# Helpers: JSON / Bedrock routing
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

# -----------------------------
# HTTP JSON
# -----------------------------
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

def _derive_soap_from_auth(auth_base: str) -> str:
    # Common pattern. Prefer token soap_instance_url if returned.
    return _norm_base(auth_base.replace(".auth.", ".soap."))

def _get_sfmc_bases(secret: dict) -> Tuple[str, str, str]:
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

    soap_base = _norm_base(
        os.getenv("SFMC_SOAP_BASE_URL", "")
        or secret.get("soap_base_url", "")
        or secret.get("soap_url", "")
        or secret.get("soapUrl", "")
    ) or _derive_soap_from_auth(auth_base)

    return auth_base, rest_base, soap_base

def _enforce_account_guardrail(secret: dict) -> None:
    if REQUIRE_SANDBOX_FLAG:
        if SFMC_ENVIRONMENT != "sandbox":
            raise ValueError("Guardrail: REQUIRE_SANDBOX_FLAG is true but SFMC_ENVIRONMENT is not 'sandbox'")

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

    token_soap = body.get("soap_instance_url") or body.get("soapInstanceUrl")
    if token_soap:
        soap_base = _norm_base(token_soap)

    _TOKEN_CACHE["access_token"] = access_token
    _TOKEN_CACHE["expires_at"] = now + expires_in
    _TOKEN_CACHE["rest_base_url"] = rest_base
    _TOKEN_CACHE["soap_base_url"] = soap_base

    return access_token, rest_base, soap_base

# -----------------------------
# SOAP helpers
# -----------------------------
SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
PARTNER_NS = "http://exacttarget.com/wsdl/partnerAPI"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

def _soap_url(soap_base: str) -> str:
    sb = _norm_base(soap_base)
    if sb.lower().endswith("service.asmx"):
        return sb
    return sb + "/Service.asmx"

def _xml_escape(s: Any) -> str:
    s = "" if s is None else str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&apos;")
    )

def _local(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag

def _et_child_text(el: ET.Element, name: str) -> Optional[str]:
    for c in list(el):
        if _local(c.tag) == name:
            return (c.text or "").strip() if c.text is not None else ""
    return None

def _et_to_dict_shallow(el: ET.Element) -> dict:
    out: Dict[str, Any] = {}
    for c in list(el):
        k = _local(c.tag)
        if len(list(c)) == 0:
            out[k] = (c.text or "").strip() if c.text is not None else ""
        else:
            # one-level nested dict for common patterns (ParentFolder -> ID)
            out[k] = _et_to_dict_shallow(c)
    return out

def _soap_post(access_token: str, soap_base: str, soap_action: str, inner_xml: str) -> Tuple[int, str]:
    url = _soap_url(soap_base)

    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:ns="{PARTNER_NS}" xmlns:xsi="{XSI_NS}">
  <soapenv:Header>
    <ns:fueloauth>{_xml_escape(access_token)}</ns:fueloauth>
  </soapenv:Header>
  <soapenv:Body>
    {inner_xml}
  </soapenv:Body>
</soapenv:Envelope>"""

    data = envelope.encode("utf-8")
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": soap_action,
    }
    req = Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=REST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, raw
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, raw
    except URLError as e:
        return 599, f"URLError: {e}"

def _soap_find_results(xml_text: str) -> List[dict]:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []

    results: List[dict] = []
    for el in root.iter():
        if _local(el.tag) == "Results":
            results.append(_et_to_dict_shallow(el))
    return results

def _soap_find_status(xml_text: str) -> Tuple[bool, List[dict]]:
    # For Create/Update, each Results typically includes StatusCode/StatusMessage/NewID
    results = _soap_find_results(xml_text)
    if not results:
        return False, []
    ok_any = False
    for r in results:
        sc = str(r.get("StatusCode") or "").upper()
        if sc == "OK":
            ok_any = True
    return ok_any, results

# -----------------------------
# Data Extension spec validation + normalisation
# -----------------------------
ALLOWED_FIELD_TYPES = {
    "Text", "Number", "Date", "Boolean", "Decimal",
    "EmailAddress", "Phone", "Locale",
}

def _validate_name(s: str, max_len: int, label: str) -> List[str]:
    w: List[str] = []
    s2 = (s or "").strip()
    if not s2:
        w.append(f"{label} is required")
        return w
    if len(s2) > max_len:
        w.append(f"{label} length > {max_len} (was {len(s2)}); will be rejected")
    return w

def _safe_path_check(folder_path: str) -> List[str]:
    w: List[str] = []
    p = (folder_path or "").strip()
    if not p:
        return w
    if ".." in p.replace("\\", "/").split("/"):
        w.append("folderPath contains '..' which is not allowed")
    if SAFE_DATAEXT_FOLDER_ROOT:
        # normalise both to forward slashes
        rp = p.replace("\\", "/").strip("/")
        rr = SAFE_DATAEXT_FOLDER_ROOT.replace("\\", "/").strip("/")
        if not rp.lower().startswith(rr.lower()):
            w.append(f"folderPath must start with SAFE_DATAEXT_FOLDER_ROOT '{SAFE_DATAEXT_FOLDER_ROOT}'")
    return w

def _normalise_fields(fields: Any) -> Tuple[List[dict], List[str]]:
    warnings: List[str] = []

    if isinstance(fields, str):
        try:
            parsed = json.loads(fields)
            fields = parsed
        except Exception:
            return [], ["fields must be a JSON array or array"]

    if not isinstance(fields, list):
        return [], ["fields must be an array"]

    if len(fields) == 0:
        return [], ["fields must not be empty"]

    if len(fields) > MAX_FIELDS:
        warnings.append(f"fields count {len(fields)} exceeds MAX_FIELDS {MAX_FIELDS}; will be clamped")
        fields = fields[:MAX_FIELDS]

    out: List[dict] = []
    seen = set()

    for idx, f in enumerate(fields, start=1):
        if not isinstance(f, dict):
            warnings.append(f"fields[{idx}] not an object; skipping")
            continue

        name = str(f.get("name") or f.get("Name") or "").strip()
        if not name:
            warnings.append(f"fields[{idx}] missing name; skipping")
            continue
        if len(name) > MAX_FIELD_NAME_LEN:
            warnings.append(f"fields[{idx}] name too long (> {MAX_FIELD_NAME_LEN}); skipping")
            continue

        key = name.lower()
        if key in seen:
            warnings.append(f"duplicate field name '{name}' found; skipping duplicate")
            continue
        seen.add(key)

        ftype = str(f.get("type") or f.get("fieldType") or f.get("FieldType") or "Text").strip()
        # normalise common aliases
        alias = {
            "string": "Text",
            "int": "Number",
            "integer": "Number",
            "bool": "Boolean",
            "datetime": "Date",
            "date": "Date",
            "decimal": "Decimal",
        }
        ftype_norm = alias.get(ftype.lower(), ftype)
        # Title-case the canonical types
        ftype_norm = ftype_norm[0].upper() + ftype_norm[1:] if ftype_norm else ftype_norm

        if ftype_norm not in ALLOWED_FIELD_TYPES:
            warnings.append(f"field '{name}' type '{ftype}' not allowed; defaulting to Text")
            ftype_norm = "Text"

        max_length = f.get("maxLength") if f.get("maxLength") is not None else f.get("MaxLength")
        precision = f.get("precision") if f.get("precision") is not None else f.get("Precision")
        scale = f.get("scale") if f.get("scale") is not None else f.get("Scale")

        is_required = f.get("isRequired")
        if is_required is None:
            is_required = f.get("required")
        if is_required is None:
            is_required = f.get("IsRequired")
        is_required = bool(is_required) if is_required is not None else False

        is_pk = f.get("isPrimaryKey")
        if is_pk is None:
            is_pk = f.get("primaryKey")
        if is_pk is None:
            is_pk = f.get("IsPrimaryKey")
        is_pk = bool(is_pk) if is_pk is not None else False

        default_value = f.get("defaultValue") if f.get("defaultValue") is not None else f.get("DefaultValue")

        # minimal sanity rules by type
        if ftype_norm == "Text":
            if max_length is None:
                max_length = 50
            try:
                max_length = int(max_length)
            except Exception:
                max_length = 50
            if max_length < 1:
                max_length = 1
            if max_length > 4000:
                warnings.append(f"field '{name}' maxLength clamped to 4000")
                max_length = 4000

        if ftype_norm in ("Number", "Boolean", "Date", "EmailAddress", "Phone", "Locale"):
            max_length = None

        if ftype_norm == "Decimal":
            try:
                precision = int(precision) if precision is not None else 18
            except Exception:
                precision = 18
            try:
                scale = int(scale) if scale is not None else 0
            except Exception:
                scale = 0
            if precision < 1:
                precision = 1
            if precision > 38:
                warnings.append(f"field '{name}' precision clamped to 38")
                precision = 38
            if scale < 0:
                scale = 0
            if scale > precision:
                warnings.append(f"field '{name}' scale clamped to precision")
                scale = precision

        out.append({
            "name": name,
            "type": ftype_norm,
            "maxLength": max_length,
            "precision": precision if ftype_norm == "Decimal" else None,
            "scale": scale if ftype_norm == "Decimal" else None,
            "isRequired": is_required,
            "isPrimaryKey": is_pk,
            "defaultValue": default_value,
        })

    if not out:
        warnings.append("no valid fields after normalisation")

    return out, warnings

def _validate_de_spec(spec: dict) -> Tuple[bool, List[str], dict]:
    warnings: List[str] = []

    name = str(spec.get("name") or "").strip()
    customer_key = str(spec.get("customerKey") or spec.get("key") or "").strip()

    warnings.extend(_validate_name(name, MAX_DE_NAME_LEN, "name"))
    warnings.extend(_validate_name(customer_key, MAX_CUSTOMER_KEY_LEN, "customerKey"))

    folder_id = spec.get("folderId") or spec.get("categoryId")
    folder_path = spec.get("folderPath")

    if not folder_id and not folder_path:
        warnings.append("Provide folderId (CategoryID) OR folderPath")

    if folder_path:
        warnings.extend(_safe_path_check(str(folder_path)))

    fields_norm, fwarn = _normalise_fields(spec.get("fields"))
    warnings.extend(fwarn)

    # primary key sanity: if any PK then force required
    pk_count = 0
    for f in fields_norm:
        if f.get("isPrimaryKey"):
            pk_count += 1
            if not f.get("isRequired"):
                warnings.append(f"field '{f['name']}' isPrimaryKey=true implies isRequired=true; will be forced")
                f["isRequired"] = True

    if pk_count == 0:
        warnings.append("No primary key fields specified. This is allowed, but consider a PK for joins/dedupe.")

    is_sendable = bool(spec.get("isSendable", False))
    sendable_field = str(spec.get("sendableField") or "").strip()
    sendable_subscriber_field = str(spec.get("sendableSubscriberField") or "").strip()

    if is_sendable:
        if not sendable_field:
            warnings.append("isSendable=true but sendableField not provided (e.g., SubscriberKey)")
        if not sendable_subscriber_field:
            warnings.append("isSendable=true but sendableSubscriberField not provided (e.g., Subscriber Key)")

    cleaned = {
        "name": name,
        "customerKey": customer_key,
        "description": str(spec.get("description") or "").strip() or None,
        "folderId": str(folder_id).strip() if folder_id is not None else None,
        "folderPath": str(folder_path).strip() if folder_path else None,
        "fields": fields_norm,
        "isSendable": is_sendable,
        "sendableField": sendable_field or None,
        "sendableSubscriberField": sendable_subscriber_field or None,
        "allowCreateMissingFolders": bool(spec.get("allowCreateMissingFolders", ALLOW_CREATE_MISSING_FOLDERS_DEFAULT)),
        "dryRun": bool(spec.get("dryRun", DEFAULT_DRY_RUN)),
    }

    ok = True
    # hard errors
    if any(x.endswith("is required") for x in warnings):
        ok = False
    if cleaned["fields"] is None or len(cleaned["fields"]) == 0:
        ok = False
    if folder_path and any("folderPath must start" in x or "contains '..'" in x for x in warnings):
        ok = False

    return ok, warnings, cleaned

# -----------------------------
# SOAP Retrieve/Create: DataFolder / DataExtension / DataExtensionField
# -----------------------------
def _soap_simple_filter(property_name: str, operator: str, value: str) -> str:
    # operator examples: equals, like
    return f"""
<ns:Filter xsi:type="ns:SimpleFilterPart">
  <ns:Property>{_xml_escape(property_name)}</ns:Property>
  <ns:SimpleOperator>{_xml_escape(operator)}</ns:SimpleOperator>
  <ns:Value>{_xml_escape(value)}</ns:Value>
</ns:Filter>""".strip()

def _soap_retrieve(object_type: str, properties: List[str], filter_xml: Optional[str] = None) -> Tuple[bool, List[dict], str]:
    access_token, _, soap_base = _get_access_token()

    props_xml = "\n".join([f"<ns:Properties>{_xml_escape(p)}</ns:Properties>" for p in properties])

    inner = f"""
<ns:RetrieveRequestMsg>
  <ns:RetrieveRequest>
    <ns:ObjectType>{_xml_escape(object_type)}</ns:ObjectType>
    {props_xml}
    {filter_xml or ""}
  </ns:RetrieveRequest>
</ns:RetrieveRequestMsg>
""".strip()

    status, raw = _soap_post(access_token, soap_base, "Retrieve", inner)
    if status < 200 or status >= 300:
        return False, [], raw

    results = _soap_find_results(raw)
    return True, results, raw

def _soap_create(objects_xml: str) -> Tuple[bool, List[dict], str]:
    access_token, _, soap_base = _get_access_token()

    inner = f"""
<ns:CreateRequest>
  {objects_xml}
</ns:CreateRequest>
""".strip()

    status, raw = _soap_post(access_token, soap_base, "Create", inner)
    if status < 200 or status >= 300:
        return False, [], raw

    ok, results = _soap_find_status(raw)
    return ok, results, raw

def _resolve_data_folder_segment(parent_id: str, segment_name: str) -> Tuple[Optional[str], List[str]]:
    """
    Resolve ONE segment by (Name + ContentType), then filter by ParentFolder.ID in-code.
    Returns folder_id or None.
    """
    warnings: List[str] = []

    ok, results, _raw = _soap_retrieve(
        object_type="DataFolder",
        properties=["ID", "Name", "ContentType", "ParentFolder.ID"],
        filter_xml=_soap_simple_filter("Name", "equals", segment_name)
    )
    if not ok:
        warnings.append("SOAP retrieve DataFolder failed")
        return None, warnings

    matches = []
    for r in results:
        name = str(r.get("Name") or "").strip()
        ctype = str(r.get("ContentType") or "").strip().lower()
        pf = r.get("ParentFolder") or {}
        pfid = str((pf.get("ID") if isinstance(pf, dict) else "") or "").strip()

        if name.lower() == segment_name.lower() and ctype == DATAEXT_FOLDER_CONTENT_TYPE.lower() and pfid == str(parent_id):
            matches.append(r)

    if len(matches) == 1:
        return str(matches[0].get("ID") or "").strip() or None, warnings
    if len(matches) > 1:
        warnings.append(f"Ambiguous folder segment '{segment_name}' under parent {parent_id} (found {len(matches)}).")
        return None, warnings

    return None, warnings

def _create_data_folder(parent_id: str, name: str) -> Tuple[Optional[str], List[str]]:
    warnings: List[str] = []

    objects_xml = f"""
<ns:Objects xsi:type="ns:DataFolder">
  <ns:Name>{_xml_escape(name)}</ns:Name>
  <ns:ContentType>{_xml_escape(DATAEXT_FOLDER_CONTENT_TYPE)}</ns:ContentType>
  <ns:ParentFolder>
    <ns:ID>{_xml_escape(parent_id)}</ns:ID>
  </ns:ParentFolder>
</ns:Objects>
""".strip()

    ok, results, raw = _soap_create(objects_xml)
    if not ok:
        warnings.append("SOAP Create DataFolder failed")
        # include a tiny hint, but not full raw unless caller requests includeRaw
        warnings.append("DataFolder create did not return OK status.")
        return None, warnings

    # try NewID first
    new_id = None
    for r in results:
        nid = str(r.get("NewID") or "").strip()
        if nid:
            new_id = nid
            break

    if new_id:
        return new_id, warnings

    # fallback: resolve again
    rid, w2 = _resolve_data_folder_segment(parent_id, name)
    warnings.extend(w2)
    return rid, warnings

def resolve_data_folder_path(folder_path: str, allow_create_missing: bool) -> Tuple[Optional[str], List[str]]:
    warnings: List[str] = []
    p = (folder_path or "").replace("\\", "/").strip().strip("/")
    if not p:
        return None, ["folderPath empty"]

    # enforce safe root prefix if configured
    wroot = _safe_path_check(p)
    if wroot:
        return None, wroot

    segments = [s for s in p.split("/") if s.strip()]
    cur = DATAEXT_ROOT_FOLDER_ID or "0"

    for seg in segments:
        seg = seg.strip()
        found, w = _resolve_data_folder_segment(cur, seg)
        warnings.extend(w)

        if found:
            cur = found
            continue

        if not allow_create_missing:
            warnings.append(f"Folder segment '{seg}' not found under parent {cur}.")
            return None, warnings

        created, w2 = _create_data_folder(cur, seg)
        warnings.extend(w2)
        if not created:
            return None, warnings
        cur = created

    return cur, warnings

def _data_extension_exists_by_customer_key(customer_key: str) -> Tuple[bool, Optional[dict], List[str]]:
    warnings: List[str] = []
    ok, results, _raw = _soap_retrieve(
        object_type="DataExtension",
        properties=["ObjectID", "CustomerKey", "Name", "CategoryID", "CreatedDate", "ModifiedDate", "IsSendable"],
        filter_xml=_soap_simple_filter("CustomerKey", "equals", customer_key)
    )
    if not ok:
        warnings.append("SOAP retrieve DataExtension failed")
        return False, None, warnings

    if len(results) >= 1:
        # could be multiple but CustomerKey should be unique
        return True, results[0], warnings

    return False, None, warnings

def _retrieve_de_fields_by_customer_key(customer_key: str, cap: int = 200) -> Tuple[List[dict], List[str]]:
    warnings: List[str] = []
    # Retrieve DataExtensionField where DataExtension.CustomerKey == customer_key
    ok, results, _raw = _soap_retrieve(
        object_type="DataExtensionField",
        properties=["Name", "FieldType", "MaxLength", "IsRequired", "IsPrimaryKey", "Precision", "Scale", "DefaultValue"],
        filter_xml=_soap_simple_filter("DataExtension.CustomerKey", "equals", customer_key)
    )
    if not ok:
        warnings.append("SOAP retrieve DataExtensionField failed")
        return [], warnings

    if len(results) > cap:
        warnings.append(f"fields capped at {cap} for output")
        results = results[:cap]
    return results, warnings

def _field_to_soap_xml(f: dict) -> str:
    # Partner API expects Fields -> Field elements
    name = f.get("name")
    ftype = f.get("type")
    max_length = f.get("maxLength")
    is_required = "true" if f.get("isRequired") else "false"
    is_pk = "true" if f.get("isPrimaryKey") else "false"
    default_value = f.get("defaultValue")

    precision = f.get("precision")
    scale = f.get("scale")

    parts = [
        f"<ns:Name>{_xml_escape(name)}</ns:Name>",
        f"<ns:FieldType>{_xml_escape(ftype)}</ns:FieldType>",
        f"<ns:IsRequired>{is_required}</ns:IsRequired>",
        f"<ns:IsPrimaryKey>{is_pk}</ns:IsPrimaryKey>",
    ]

    if ftype == "Text" and max_length is not None:
        parts.append(f"<ns:MaxLength>{int(max_length)}</ns:MaxLength>")

    if ftype == "Decimal":
        if precision is not None:
            parts.append(f"<ns:Precision>{int(precision)}</ns:Precision>")
        if scale is not None:
            parts.append(f"<ns:Scale>{int(scale)}</ns:Scale>")

    if default_value is not None and str(default_value).strip() != "":
        parts.append(f"<ns:DefaultValue>{_xml_escape(default_value)}</ns:DefaultValue>")

    return "<ns:Field>\n" + "\n".join(parts) + "\n</ns:Field>"

def _create_data_extension_soap(spec: dict) -> Tuple[bool, List[dict], str]:
    """
    Create DataExtension via SOAP CreateRequest.
    """
    name = spec["name"]
    customer_key = spec["customerKey"]
    description = spec.get("description")
    category_id = spec["folderId"]

    is_sendable = spec.get("isSendable", False)
    sendable_field = spec.get("sendableField")
    sendable_subscriber_field = spec.get("sendableSubscriberField")

    fields_xml = "\n".join([_field_to_soap_xml(f) for f in spec["fields"]])

    sendable_xml = ""
    if is_sendable:
        # Keep minimal; user must supply both names or it may fail.
        sendable_xml = f"""
<ns:IsSendable>true</ns:IsSendable>
<ns:SendableDataExtensionField>
  <ns:Name>{_xml_escape(sendable_field or "")}</ns:Name>
</ns:SendableDataExtensionField>
<ns:SendableSubscriberField>
  <ns:Name>{_xml_escape(sendable_subscriber_field or "")}</ns:Name>
</ns:SendableSubscriberField>
""".strip()
    else:
        sendable_xml = "<ns:IsSendable>false</ns:IsSendable>"

    objects_xml = f"""
<ns:Objects xsi:type="ns:DataExtension">
  <ns:CustomerKey>{_xml_escape(customer_key)}</ns:CustomerKey>
  <ns:Name>{_xml_escape(name)}</ns:Name>
  {f"<ns:Description>{_xml_escape(description)}</ns:Description>" if description else ""}
  <ns:CategoryID>{_xml_escape(category_id)}</ns:CategoryID>
  {sendable_xml}
  <ns:Fields>
    {fields_xml}
  </ns:Fields>
</ns:Objects>
""".strip()

    ok, results, raw = _soap_create(objects_xml)
    return ok, results, raw

# -----------------------------
# Tool handlers
# -----------------------------
def _handle_validate_de_spec(params: Dict[str, Any]) -> Tuple[int, dict]:
    ok, warnings, cleaned = _validate_de_spec(params or {})
    return 200, {
        "ok": ok,
        "tool": "data_extension_validate",
        "input": params,
        "cleaned": cleaned,
        "warnings": warnings,
    }

def _handle_create_de(params: Dict[str, Any]) -> Tuple[int, dict]:
    include_raw = bool(params.get("includeRaw", False))

    ok, warnings, cleaned = _validate_de_spec(params or {})
    if not ok:
        return 400, {
            "ok": False,
            "tool": "data_extension_create",
            "error": "VALIDATION_FAILED",
            "warnings": warnings,
            "cleaned": cleaned,
        }

    # Resolve folderId if folderPath provided
    folder_warnings: List[str] = []
    if not cleaned.get("folderId") and cleaned.get("folderPath"):
        folder_id, fw = resolve_data_folder_path(
            cleaned["folderPath"],
            allow_create_missing=bool(cleaned.get("allowCreateMissingFolders"))
        )
        folder_warnings.extend(fw)
        if not folder_id:
            return 400, {
                "ok": False,
                "tool": "data_extension_create",
                "error": "FOLDER_RESOLUTION_FAILED",
                "warnings": warnings + folder_warnings,
                "cleaned": cleaned,
            }
        cleaned["folderId"] = str(folder_id)

    # If still no folderId, fail
    if not cleaned.get("folderId"):
        return 400, {
            "ok": False,
            "tool": "data_extension_create",
            "error": "MISSING_FOLDER_ID",
            "warnings": warnings + folder_warnings,
            "cleaned": cleaned,
        }

    # Idempotency: prevent overwrite by default
    exists, existing, ew = _data_extension_exists_by_customer_key(cleaned["customerKey"])
    all_warn = warnings + folder_warnings + ew
    if exists:
        out = {
            "ok": False,
            "tool": "data_extension_create",
            "error": "DATA_EXTENSION_ALREADY_EXISTS",
            "customerKey": cleaned["customerKey"],
            "existing": existing,
            "warnings": all_warn,
            "hint": "Choose a new customerKey, or add an explicit update tool (not provided here).",
        }
        return 409, out

    # Dry-run
    if bool(cleaned.get("dryRun", DEFAULT_DRY_RUN)):
        # Return a preview of what would be created (no SOAP raw by default)
        return 200, {
            "ok": True,
            "tool": "data_extension_create",
            "dryRun": True,
            "cleaned": cleaned,
            "warnings": all_warn,
            "preview": {
                "name": cleaned["name"],
                "customerKey": cleaned["customerKey"],
                "folderId": cleaned["folderId"],
                "fieldCount": len(cleaned["fields"] or []),
                "isSendable": cleaned.get("isSendable", False),
            }
        }

    # Execute create
    created_ok, results, raw = _create_data_extension_soap(cleaned)

    if not created_ok:
        resp = {
            "ok": False,
            "tool": "data_extension_create",
            "error": "SFMC_CREATE_FAILED",
            "warnings": all_warn,
            "sfmcResults": results,
        }
        if include_raw:
            resp["soapRaw"] = raw
        return 502, resp

    # post-check retrieve
    exists2, existing2, ew2 = _data_extension_exists_by_customer_key(cleaned["customerKey"])
    all_warn.extend(ew2)

    resp2 = {
        "ok": True,
        "tool": "data_extension_create",
        "dryRun": False,
        "cleaned": cleaned,
        "sfmcResults": results,
        "created": existing2 if exists2 else {"customerKey": cleaned["customerKey"], "name": cleaned["name"]},
        "warnings": all_warn,
    }
    if include_raw:
        resp2["soapRaw"] = raw

    return 200, resp2


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
        logger.info("Parsed Bedrock params keys: %s", list(params.keys()))

        if api_path in ("/validatedataextensionspec", "/validatede"):
            status, body = _handle_validate_de_spec(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/createdataextension", "/createde"):
            status, body = _handle_create_de(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)


        return _bedrock_actiongroup_response(event, {"ok": False, "error": f"Unknown apiPath: {api_path}"}, http_code=400)

    # Direct invoke (API Gateway-style)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event).lower()

    if path in ("/validatedataextensionspec", "/validatede"):
        status, body = _handle_validate_de_spec(params)
        return _json_response(body, status)

    if path in ("/createdataextension", "/createde"):
        status, body = _handle_create_de(params)
        return _json_response(body, status)


    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
