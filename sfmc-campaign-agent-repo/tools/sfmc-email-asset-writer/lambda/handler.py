import base64
import json
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")


# -----------------------------
# Bedrock event helpers
# -----------------------------

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

    return _normalize_api_path(event.get("rawPath") or event.get("path") or "")


def _get_http_method(event: dict) -> str:
    m = event.get("httpMethod")
    if m:
        return str(m).upper()

    agi = event.get("actionGroupInvocationInput", {}) or {}
    v = agi.get("verb") or agi.get("httpMethod")
    if v:
        return str(v).upper()

    return "POST"


def _is_bedrock_event(event: dict) -> bool:
    return ("messageVersion" in event and "response" not in event) or ("actionGroupInvocationInput" in event)


def _bedrock_actiongroup_response(event: dict, body_obj: Any, http_code: int = 200) -> dict:
    if isinstance(body_obj, str):
        body_str = body_obj
    else:
        body_str = json.dumps(body_obj, ensure_ascii=False)

    resp = {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": event.get("actionGroup") or (event.get("actionGroupInvocationInput", {}) or {}).get("actionGroupName"),
            "apiPath": event.get("apiPath") or _get_api_path(event),
            "httpMethod": event.get("httpMethod") or _get_http_method(event),
            "httpStatusCode": int(http_code),
            "responseBody": {"application/json": {"body": body_str}},
        },
    }

    if isinstance(event.get("sessionAttributes"), dict):
        resp["sessionAttributes"] = event["sessionAttributes"]
    if isinstance(event.get("promptSessionAttributes"), dict):
        resp["promptSessionAttributes"] = event["promptSessionAttributes"]

    return resp


def _http_response(body_obj: Any, http_code: int = 200) -> dict:
    return {
        "statusCode": int(http_code),
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body_obj, ensure_ascii=False) if not isinstance(body_obj, str) else body_obj,
    }


# -----------------------------
# Parameter parsing (Bedrock typed parameters)
# -----------------------------

def _coerce_typed_value(typ: str, val: Any) -> Any:
    typ = (typ or "").lower()

    if typ == "integer":
        try:
            return int(val)
        except Exception:
            return None

    if typ == "number":
        try:
            return float(val)
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


def _maybe_parse_json_str(x: Any) -> Any:
    if not isinstance(x, str):
        return x
    s = x.strip()
    if not s:
        return x
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        try:
            return json.loads(s)
        except Exception:
            return x
    return x


def _parse_bedrock_params(event: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    plist = event.get("parameters") or (event.get("actionGroupInvocationInput", {}) or {}).get("parameters") or []
    if isinstance(plist, dict):
        plist = [plist]
    if isinstance(plist, list):
        for p in plist:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(p.get("type"), _maybe_parse_json_str(p.get("value")))

    rb = event.get("requestBody") or (event.get("actionGroupInvocationInput", {}) or {}).get("requestBody") or {}
    rb = _maybe_parse_json_str(rb)
    if not isinstance(rb, dict):
        return out

    content = rb.get("content") or {}
    content = _maybe_parse_json_str(content)
    if not isinstance(content, dict):
        return out

    aj = content.get("application/json") or content.get("application_json") or content.get("application-json") or {}
    aj = _maybe_parse_json_str(aj)

    if isinstance(aj, dict) and isinstance(aj.get("properties"), list):
        for it in aj["properties"]:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), _maybe_parse_json_str(it.get("value")))
        return out

    if isinstance(aj, dict) and isinstance(aj.get("properties"), dict):
        props = aj.get("properties") or {}
        for name, meta in props.items():
            if not name:
                continue
            if isinstance(meta, dict):
                out[name] = _coerce_typed_value(meta.get("type"), _maybe_parse_json_str(meta.get("value")))
            else:
                out[name] = _maybe_parse_json_str(meta)
        return out

    if isinstance(aj, dict):
        out.update(aj)
        return out

    return out


# -----------------------------
# Secrets + SFMC auth
# -----------------------------

_cached_token = {"access_token": None, "expires_at": 0, "rest_base": None}


def _clamp_int(x: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(x)
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


def _get_secret_json(secret_ref: str) -> dict:
    resp = secrets.get_secret_value(SecretId=secret_ref)
    s = resp.get("SecretString") or "{}"
    try:
        return json.loads(s)
    except Exception:
        raise ValueError("SecretString is not valid JSON")


def _get_allowed_account_id() -> str:
    return (os.getenv("SFMC_ALLOWED_ACCOUNT_ID") or "").strip()


def _enforce_allowed_account_id(secret_cfg: dict) -> None:
    allowed = _get_allowed_account_id()
    if not allowed:
        return

    acct = secret_cfg.get("account_id") or secret_cfg.get("accountId")
    acct = str(acct or "").strip()

    if not acct:
        raise ValueError("SFMC_ALLOWED_ACCOUNT_ID is set but secret is missing account_id/accountId.")
    if acct != allowed:
        raise ValueError("Secret account_id does not match SFMC_ALLOWED_ACCOUNT_ID (sandbox guardrail).")


def _get_sfmc_bases(secret_cfg: dict) -> Tuple[str, str]:
    auth_base = (
        os.getenv("SFMC_AUTH_BASE_URL", "").strip()
        or os.getenv("auth_url", "").strip()
        or secret_cfg.get("auth_base_url", "")
        or secret_cfg.get("authBaseUrl", "")
        or secret_cfg.get("auth_url", "")
        or secret_cfg.get("authUrl", "")
    ).strip().rstrip("/")

    rest_base = (
        os.getenv("SFMC_REST_BASE_URL", "").strip()
        or secret_cfg.get("rest_base_url", "")
        or secret_cfg.get("restBaseUrl", "")
        or secret_cfg.get("rest_url", "")
        or secret_cfg.get("restUrl", "")
    ).strip().rstrip("/")

    if not auth_base:
        raise ValueError("Missing auth base URL (set SFMC_AUTH_BASE_URL/auth_url env or include in secret)")

    if not rest_base:
        rest_base = auth_base.replace(".auth.", ".rest.")
    return auth_base, rest_base


def _sfmc_get_token(secret_cfg: dict) -> dict:
    _enforce_allowed_account_id(secret_cfg)

    now = int(time.time())
    if _cached_token["access_token"] and now < int(_cached_token["expires_at"] or 0) - 30:
        return _cached_token

    client_id = secret_cfg.get("client_id") or secret_cfg.get("clientId")
    client_secret = secret_cfg.get("client_secret") or secret_cfg.get("clientSecret")
    if not client_id or not client_secret:
        raise ValueError("Secret must include client_id/client_secret (or clientId/clientSecret)")

    auth_base, rest_base = _get_sfmc_bases(secret_cfg)

    payload = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    acct = secret_cfg.get("account_id") or secret_cfg.get("accountId")
    if acct:
        payload["account_id"] = acct

    timeout_s = _clamp_int(os.getenv("SFMC_TOKEN_TIMEOUT", "20"), 20, 5, 60)

    req = Request(
        url=f"{auth_base}/v2/token",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(req, timeout=timeout_s) as r:
            body = json.loads(r.read().decode("utf-8"))
    except HTTPError as e:
        raise RuntimeError(f"SFMC token HTTPError {e.code}: {e.read().decode('utf-8', errors='ignore')}")
    except URLError as e:
        raise RuntimeError(f"SFMC token URLError: {str(e)}")

    access_token = body.get("access_token")
    expires_in = int(body.get("expires_in") or 1200)
    rest_base2 = (body.get("rest_instance_url") or "").rstrip("/") or rest_base

    if not access_token or not rest_base2:
        raise RuntimeError("SFMC token response missing access_token or rest base URL")

    _cached_token["access_token"] = access_token
    _cached_token["expires_at"] = now + expires_in
    _cached_token["rest_base"] = rest_base2
    return _cached_token


def _sfmc_request(method: str, url: str, access_token: str, json_body: Optional[dict] = None) -> dict:
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None

    timeout_s = _clamp_int(os.getenv("SFMC_API_TIMEOUT", "30"), 30, 5, 120)

    req = Request(url=url, data=data, headers=headers, method=method.upper())
    try:
        with urlopen(req, timeout=timeout_s) as r:
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"SFMC API HTTPError {e.code}: {err}")
    except URLError as e:
        raise RuntimeError(f"SFMC API URLError: {str(e)}")


# -----------------------------
# Core operation
# -----------------------------

def _extract_blueprint(params: Dict[str, Any]) -> Tuple[Dict[str, Any], list]:
    warnings = []
    blueprint = params.get("emailBlueprint") if isinstance(params.get("emailBlueprint"), dict) else {}

    def pick(key: str, default: Any = "") -> Any:
        if key in params:
            return params.get(key)
        if key in blueprint:
            return blueprint.get(key)
        return default

    brand = (pick("brand") or "Dodo").strip()
    category_id = pick("categoryId", None)
    name = (pick("assetName") or pick("name") or "").strip()
    folder_path = (pick("folderPath") or "").strip()
    asset_type_name = (pick("assetTypeName") or "htmlemail").strip() or "htmlemail"
    subject = (pick("subject") or "").strip()

    preheader = None
    if "preheader" in params:
        preheader = params.get("preheader")
    elif "preheader" in blueprint:
        preheader = blueprint.get("preheader")

    html_b64 = pick("htmlContentB64")
    html = (pick("htmlContent") or "").strip()
    text_content = (pick("textContent") or "").strip()

    if not name:
        warnings.append("emailBlueprint.name is missing; supply assetName/name in the request.")
    if not folder_path:
        warnings.append("emailBlueprint.folderPath is missing; use folder-resolver to determine categoryId.")

    return {
        "brand": brand,
        "categoryId": category_id,
        "name": name,
        "folderPath": folder_path,
        "assetTypeName": asset_type_name,
        "subject": subject,
        "preheader": preheader,
        "htmlContent": html,
        "htmlContentB64": html_b64,
        "textContent": text_content,
    }, warnings


def _create_email_asset(params: Dict[str, Any]) -> Tuple[int, dict]:
    brand = (params.get("brand") or "Dodo").strip()
    if brand.lower() != "dodo":
        return 400, {
            "created": False,
            "error": "Only brand=Dodo is supported.",
            "warnings": ["Only brand=Dodo is supported."],
        }

    secret_ref = (os.getenv("SFMC_SECRET_ARN") or os.getenv("SFMC_SECRET_ID") or "").strip()
    if not secret_ref:
        return 500, {
            "created": False,
            "error": "Missing SFMC secret reference",
            "message": "Missing SFMC_SECRET_ARN or SFMC_SECRET_ID env var.",
            "warnings": ["Missing SFMC_SECRET_ARN or SFMC_SECRET_ID env var."],
        }

    category_id = params.get("categoryId")
    if category_id is None:
        extra_warnings = params.get("warnings", [])
        if params.get("folderPath"):
            extra_warnings = extra_warnings + ["folderPath provided without categoryId. Use sfmc-folder-resolver first."]
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": "categoryId is required. Use sfmc-folder-resolver to obtain it.",
            "warnings": ["categoryId is required."] + extra_warnings,
        }

    category_id = _clamp_int(category_id, 0, 0, 2_000_000_000)
    if category_id <= 0:
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": "categoryId must be >= 1.",
            "categoryId": category_id,
            "warnings": ["categoryId must be >= 1."] + params.get("warnings", []),
        }

    asset_type_name = (params.get("assetTypeName") or "htmlemail").strip().lower()
    if asset_type_name != "htmlemail":
        return 400, {
            "created": False,
            "error": "Unsupported asset type",
            "message": "Only assetTypeName=htmlemail is supported.",
            "warnings": ["Only assetTypeName=htmlemail is supported."] + params.get("warnings", []),
        }

    name = (params.get("name") or "").strip()
    subject = (params.get("subject") or "").strip()
    preheader = params.get("preheader")

    if preheader is None:
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": "preheader is required (can be empty string).",
            "warnings": ["preheader is required (can be empty string)."] + params.get("warnings", []),
        }

    if not name or not subject:
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": "name and subject are required.",
            "warnings": ["name and subject are required."] + params.get("warnings", []),
        }

    html = ""
    if params.get("htmlContentB64"):
        try:
            html = base64.b64decode(str(params["htmlContentB64"]).encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return 400, {
                "created": False,
                "error": "Bad request",
                "message": "htmlContentB64 was not valid base64.",
                "warnings": ["htmlContentB64 was not valid base64."] + params.get("warnings", []),
            }
    else:
        html = (params.get("htmlContent") or "").strip()

    if not html:
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": "htmlContent (or htmlContentB64) is required.",
            "warnings": ["htmlContent (or htmlContentB64) is required."] + params.get("warnings", []),
        }

    max_html_chars = _clamp_int(os.getenv("MAX_HTML_CHARS", "200000"), 200000, 10000, 1000000)
    if len(html) > max_html_chars:
        return 400, {
            "created": False,
            "error": "Bad request",
            "message": f"HTML exceeded MAX_HTML_CHARS ({max_html_chars}).",
            "warnings": ["HTML too large."] + params.get("warnings", []),
        }

    try:
        secret_cfg = _get_secret_json(secret_ref)
        tok = _sfmc_get_token(secret_cfg)
        access_token = tok["access_token"]
        rest_base = tok["rest_base"]

        payload = {
            "name": name,
            "assetType": {"name": "htmlemail", "id": 208},
            "category": {"id": category_id},
            "views": {
                "html": {"content": html},
                "subjectline": {"content": subject},
                "preheader": {"content": preheader or ""},
            },
        }

        text_content = (params.get("textContent") or "").strip()
        if text_content:
            payload["views"]["text"] = {"content": text_content}

        url = f"{rest_base}/asset/v1/content/assets"
        created = _sfmc_request("POST", url, access_token, payload)

        asset_id = str(created.get("id") or "")
        warnings = params.get("warnings", [])
        if not asset_id:
            warnings.append("SFMC response did not include an id field.")

        return 200, {
            "created": True,
            "categoryId": category_id,
            "assetId": asset_id,
            "warnings": warnings,
        }
    except Exception as e:
        logger.exception("createEmailAsset failed")
        return 502, {
            "created": False,
            "error": "SFMC dependency failed",
            "message": str(e),
            "categoryId": category_id,
            "warnings": params.get("warnings", []),
        }


# -----------------------------
# Lambda entrypoint
# -----------------------------

def lambda_handler(event, context):
    logger.info("Incoming event keys: %s", list(event.keys()))

    if _is_bedrock_event(event):
        api_path = _get_api_path(event).lower()
        params = _parse_bedrock_params(event)

        if api_path in ("/writeemailasset", "/createemailasset"):
            blueprint, warnings = _extract_blueprint(params)
            blueprint["warnings"] = warnings
            status, body = _create_email_asset(blueprint)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        return _bedrock_actiongroup_response(event, {"error": f"Unknown apiPath: {api_path}", "created": False}, http_code=400)

    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    api_path = _get_api_path(event).lower()
    if api_path in ("/writeemailasset", "/createemailasset"):
        blueprint, warnings = _extract_blueprint(params)
        blueprint["warnings"] = warnings
        status, body = _create_email_asset(blueprint)
        return _http_response(body, status)

    return _http_response({"error": f"Unknown apiPath: {api_path}", "created": False}, 400)
