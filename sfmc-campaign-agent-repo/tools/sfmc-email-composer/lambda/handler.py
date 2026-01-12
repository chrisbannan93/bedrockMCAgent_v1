import os
import json
import base64
import time
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

secrets = boto3.client("secretsmanager")
bedrock_agent_rt = boto3.client("bedrock-agent-runtime")
bedrock_rt = boto3.client("bedrock-runtime")

# -----------------------------
# Bedrock event helpers (supports both "flattened" and nested shapes)
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


def _get_action_group_name(event: dict) -> str:
    ag = event.get("actionGroup")
    if ag:
        return str(ag)

    agi = event.get("actionGroupInvocationInput", {}) or {}
    ag2 = agi.get("actionGroupName") or agi.get("actionGroup")
    return str(ag2 or "")


def _is_bedrock_action_group_event(event: dict) -> bool:
    # Bedrock action group events always have messageVersion OR actionGroupInvocationInput
    return ("messageVersion" in event and "response" not in event) or ("actionGroupInvocationInput" in event)


def _bedrock_actiongroup_response(event: dict, body_obj: Any, http_code: int = 200) -> dict:
    if isinstance(body_obj, str):
        body_str = body_obj
    else:
        body_str = json.dumps(body_obj, ensure_ascii=False)

    resp = {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": event.get("actionGroup") or _get_action_group_name(event),
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
# Bedrock typed parameter parsing (matches AWS input shape)
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

        if "<item>" in s and "</item>" in s:
            items = re.findall(r"<item>(.*?)</item>", s, flags=re.DOTALL)
            return [i.strip() for i in items if i.strip()]

        return [x.strip() for x in s.split(",") if x.strip()]

    # pass-through for "string", "object", etc.
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
    """
    Supports multiple Bedrock action group invocation shapes:

    - event.parameters: [{"name","type","value"}, ...]
    - requestBody.content.application/json.properties: LIST of {"name","type","value"}
    - requestBody.content.application/json.properties: DICT of {"paramName": {"type","value"}}
    - requestBody.content.application/json.body: dict OR JSON string
    - requestBody.content.application/json: a dict of fields
    """
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

    # Shape A1: {"properties":[{"name","type","value"}, ...]}
    if isinstance(aj, dict) and isinstance(aj.get("properties"), list):
        for it in aj["properties"]:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(it.get("type"), _maybe_parse_json_str(it.get("value")))
        return out

    # Shape A2: {"properties": { "brand": {"type":"string","value":"Dodo"}, ...}}
    if isinstance(aj, dict) and isinstance(aj.get("properties"), dict):
        props = aj.get("properties") or {}
        for name, meta in props.items():
            if not name:
                continue
            if isinstance(meta, dict):
                v = meta.get("value")
                t = meta.get("type")
                if v is None and "default" in meta:
                    v = meta.get("default")
                out[name] = _coerce_typed_value(t, _maybe_parse_json_str(v))
            else:
                out[name] = meta
        return out

    # Shape B: {"body": {...}} OR {"body":"{...json...}"}
    if isinstance(aj, dict) and "body" in aj:
        body = _maybe_parse_json_str(aj.get("body"))
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

    # Shape C: {"brand":"Dodo", ...}
    if isinstance(aj, dict):
        out.update(aj)
        return out

    return out


def _read_request_json(event: dict) -> dict:
    if _is_bedrock_action_group_event(event):
        return _parse_bedrock_params(event)

    body_in = event.get("body")
    if isinstance(body_in, str) and event.get("isBase64Encoded") is True:
        try:
            body_in = base64.b64decode(body_in.encode("utf-8")).decode("utf-8", errors="replace")
        except Exception:
            return {}

    try:
        return json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        return {}


# -----------------------------
# Small input helpers
# -----------------------------
def _normalize_brand(req: dict) -> str:
    b = req.get("brand")
    if not isinstance(b, str) or not b.strip():
        return "Dodo"
    b = b.strip()
    if b.lower() == "dodo":
        return "Dodo"
    return b


def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes", "y")
    if isinstance(val, (int, float)):
        return val != 0
    return False


def _looks_like_xml(s: str) -> bool:
    if not s:
        return False
    return bool("<" in s and ">" in s and re.search(r"</?\w+[^>]*>", s))


def _strip_bad_json_control_chars(s: str) -> str:
    # Remove ASCII control chars that commonly break json.loads (keep \t \n \r)
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s or "")


def _clamp_int(x: Any, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(x)
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


def _clamp_float(x: Any, default: float, min_v: float, max_v: float) -> float:
    try:
        v = float(x)
    except Exception:
        v = default
    return max(min_v, min(max_v, v))


# -----------------------------
# Secrets + SFMC auth (with sandbox guardrail)
# -----------------------------
_cached_token = {"access_token": None, "expires_at": 0, "rest_base": None}


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
# RAG retrieve (KB)
# -----------------------------
def _retrieve_style(kb_id: str, query_text: str, num_results: int) -> Tuple[List[dict], List[str]]:
    warnings: List[str] = []
    if not kb_id:
        return [], ["No kbId provided; proceeding without RAG."]

    try:
        resp = bedrock_agent_rt.retrieve(
            knowledgeBaseId=kb_id,
            retrievalQuery={"text": query_text},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": num_results}},
        )
        results = resp.get("retrievalResults") or []
        sources: List[dict] = []
        for r in results:
            content = (r.get("content") or {}).get("text") or ""
            loc = r.get("location") or {}
            s3loc = (loc.get("s3Location") or {}).get("uri")
            score = r.get("score")
            sources.append(
                {"sourceUri": s3loc or "", "score": float(score) if score is not None else 0.0, "excerpt": content[:600]}
            )
        return sources, warnings
    except Exception:
        warnings.append("RAG retrieve failed; proceeding without RAG.")
        logger.exception("RAG retrieve error")
        return [], warnings


def _rag_sources_from_ragcontext(rag_context: Any) -> List[dict]:
    sources: List[dict] = []
    if not rag_context or not isinstance(rag_context, list):
        return sources

    for i, item in enumerate(rag_context[:10], start=1):
        if isinstance(item, str):
            excerpt = item
            source_uri = f"ragContext:{i}"
        elif isinstance(item, dict):
            excerpt = item.get("excerpt") or item.get("text") or json.dumps(item, ensure_ascii=False)
            source_uri = item.get("sourceUri") or f"ragContext:{i}"
        else:
            excerpt = str(item)
            source_uri = f"ragContext:{i}"

        sources.append({"sourceUri": source_uri, "score": 1.0, "excerpt": str(excerpt)[:600]})
    return sources


def _sanitize_rag_context(req: dict) -> Tuple[Optional[list], List[str]]:
    warnings: List[str] = []
    rc = req.get("ragContext")
    if not rc:
        return None, warnings
    if not isinstance(rc, list):
        warnings.append("ragContext was not an array; ignoring and falling back to KB retrieval.")
        return None, warnings

    for item in rc[:10]:
        if isinstance(item, str):
            if _looks_like_xml(item) or "search_quality_reflection" in item or "search_quality_score" in item:
                warnings.append("ragContext contained non-style metadata/XML; ignoring and falling back to KB retrieval.")
                return None, warnings
        elif isinstance(item, dict):
            bad_keys = {"search_quality_reflection", "search_quality_score", "ragContext"}
            if any(k in item for k in bad_keys):
                warnings.append("ragContext contained non-style metadata keys; ignoring and falling back to KB retrieval.")
                return None, warnings

    return rc[:10], warnings


# -----------------------------
# Writer (Claude via Bedrock)
# -----------------------------
def _invoke_claude(model_id: str, prompt: str, max_tokens: int, temperature: float) -> str:
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    }

    resp = bedrock_rt.invoke_model(
        modelId=model_id,
        body=json.dumps(body).encode("utf-8"),
        accept="application/json",
        contentType="application/json",
    )

    raw = resp["body"].read().decode("utf-8")
    data = json.loads(raw)

    parts = data.get("content") or []
    if isinstance(parts, list):
        texts = []
        for p in parts:
            if isinstance(p, dict) and "text" in p:
                texts.append(p.get("text") or "")
        return "".join(texts)
    return ""


def _build_writer_prompt(req: dict, rag_sources: List[dict], template_html: str) -> str:
    """
    Request BASE64 HTML for JSON stability; discourage giant boilerplate.
    """
    brief = (req.get("brief") or "").strip()
    normalized_brief = req.get("normalizedBrief")
    wants_template = bool(template_html)

    if not brief and normalized_brief:
        try:
            brief = json.dumps(normalized_brief, ensure_ascii=False)
        except Exception:
            brief = str(normalized_brief)

    tone = (req.get("tone") or "").strip()
    email_goal = (req.get("emailGoal") or "").strip()
    audience = (req.get("audienceSummary") or "").strip()

    cta_text = (req.get("ctaText") or req.get("cta") or "").strip()
    cta_url = (req.get("ctaUrl") or "").strip()

    required_links = req.get("requiredLinks") or []
    personalization_tokens = req.get("personalizationTokens") or []
    required_blocks = req.get("requiredBlocks") or []

    rag_block = ""
    if rag_sources:
        lines = []
        for i, s in enumerate(rag_sources[:10], start=1):
            lines.append(
                f"[RAG {i}] sourceUri={s.get('sourceUri','')} score={s.get('score',0)}\n{s.get('excerpt','')}"
            )
        rag_block = "\n\n".join(lines)

    html_instructions = """
CRITICAL OUTPUT RULE:
- The "html" field MUST be BASE64-encoded HTML (UTF-8) AND MUST be a single line with NO spaces, NO \\n, NO \\r, NO \\t.
"""

    if wants_template:
        html_instructions = """
CRITICAL OUTPUT RULE:
- The "html" field MUST be BASE64-encoded HTML (UTF-8) of ONLY the body content (no <html>, <head>, or <body> tags).
- The body content will be injected into a fixed container template. Do NOT include outer document wrappers.
- The "html" field MUST be a single line with NO spaces, NO \\n, NO \\r, NO \\t.
"""

    return f"""
You are an internal SFMC SANDBOX email copy + HTML composer for the AU brand "Dodo" (telecommunications).
You MUST output ONLY a single valid JSON object (no markdown, no commentary, no code fences, no extra text).

Hard rules:
- Brand is Dodo ONLY.
- Do NOT include any SFMC IDs, UUIDs, or internal identifiers.
- Email HTML must be table-based + inline styles, no scripts, no external CSS.
- Keep tone: clear, friendly, practical, Dodo-ish.
- If RAG guidance is present, follow it as highest priority.
- IMPORTANT: Keep the email reasonably compact. Do NOT paste huge boilerplate/footer/navigation blocks.
  If a footer is needed, keep it minimal. Aim to keep raw HTML under ~10KB.

{html_instructions}

Return JSON with EXACT keys:
{{
  "subject": "...",
  "preheader": "...",
  "html": "BASE64_HTML_UTF8_SINGLE_LINE",
  "warnings": ["...optional"]
}}

Input:
tone: {tone}
brief: {brief}
emailGoal: {email_goal}
audienceSummary: {audience}
ctaText: {cta_text}
ctaUrl: {cta_url}
requiredLinks: {json.dumps(required_links, ensure_ascii=False)}
personalizationTokens: {json.dumps(personalization_tokens, ensure_ascii=False)}
requiredBlocks: {json.dumps(required_blocks, ensure_ascii=False)}

RAG_STYLE_GUIDANCE (may be empty):
{rag_block}
""".strip()


def _fallback_extract_model_fields(text: str) -> Optional[dict]:
    """
    Salvage subject/preheader/html from JSON-ish output even if json.loads fails.
    """
    if not text:
        return None

    def _cap(key: str) -> str:
        m = re.search(rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"', text, flags=re.DOTALL)
        if not m:
            return ""
        raw = m.group(1)
        try:
            return json.loads(f'"{raw}"')
        except Exception:
            return raw

    subject = _cap("subject").strip()
    preheader = _cap("preheader").strip()
    html = _cap("html").strip()

    if html:
        html = re.sub(r"\s+", "", html)

    warnings: List[str] = []
    wm = re.search(r'"warnings"\s*:\s*(\[[\s\S]*?\])', text, flags=re.DOTALL)
    if wm:
        try:
            w = json.loads(wm.group(1))
            if isinstance(w, list):
                warnings = [str(x) for x in w]
        except Exception:
            pass

    if subject or preheader or html:
        out = {"subject": subject, "preheader": preheader, "html": html}
        if warnings:
            out["warnings"] = warnings
        return out

    return None


def _extract_json_object(text: str) -> Optional[dict]:
    if not text or not isinstance(text, str):
        return None

    text = _strip_bad_json_control_chars(text).strip()
    if not text:
        return None

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception as e:
        logger.info("Writer json.loads failed (direct): %s", str(e))

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = _strip_bad_json_control_chars(text[start : end + 1])
        try:
            obj = json.loads(snippet)
            return obj if isinstance(obj, dict) else None
        except Exception as e:
            logger.info("Writer json.loads failed (snippet): %s", str(e))

    salvaged = _fallback_extract_model_fields(text)
    if salvaged:
        return salvaged

    return None


def _try_b64_decode_html(s: str) -> Optional[str]:
    if not s or not isinstance(s, str):
        return None

    s2 = re.sub(r"\s+", "", s)

    if "<" in s2 or ">" in s2:
        return None

    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s2 or ""):
        return None

    try:
        decoded = base64.b64decode(s2, validate=True).decode("utf-8", errors="replace")
    except Exception:
        try:
            pad = (-len(s2)) % 4
            s3 = s2 + ("=" * pad)
            decoded = base64.b64decode(s3, validate=False).decode("utf-8", errors="replace")
        except Exception:
            return None

    if "<" in decoded and ">" in decoded and re.search(r"</?\w+[^>]*>", decoded):
        return decoded
    return None


def _as_html_plain_and_b64(model_html_field: str) -> Tuple[str, str, bool]:
    decoded = _try_b64_decode_html(model_html_field)
    if decoded is not None:
        html_plain = decoded
        html_b64 = re.sub(r"\s+", "", model_html_field or "")
        return html_plain, html_b64, True

    html_plain = model_html_field or ""
    html_b64 = base64.b64encode(html_plain.encode("utf-8")).decode("utf-8") if html_plain else ""
    return html_plain, html_b64, False


def _extract_body_fragment(html: str) -> Tuple[str, bool]:
    if not html:
        return "", False
    m = re.search(r"<body[^>]*>(?P<body>[\s\S]*?)</body>", html, flags=re.IGNORECASE)
    if m:
        return m.group("body").strip(), True
    return html, False


def _apply_template(
    template_html: str,
    body_html: str,
    slot_key: str,
    slot_label: str,
) -> Tuple[str, List[str]]:
    warnings: List[str] = []
    if not template_html:
        return body_html, warnings

    placeholder = "{{BODY_HTML}}"
    if placeholder not in template_html:
        slot_key = (slot_key or "").strip()
        slot_label = (slot_label or "").strip()
        slot_pattern = ""
        if slot_key:
            slot_pattern = rf"<div\s+[^>]*data-type=\"slot\"[^>]*data-key=\"{re.escape(slot_key)}\"[^>]*>\s*</div>"
        elif slot_label:
            slot_pattern = rf"<div\s+[^>]*data-type=\"slot\"[^>]*data-label=\"{re.escape(slot_label)}\"[^>]*>\s*</div>"
        if not slot_pattern:
            warnings.append(
                "templateHtml provided but missing {{BODY_HTML}} placeholder; returning generated HTML only."
            )
            return body_html, warnings

        slot_match = re.search(slot_pattern, template_html, flags=re.IGNORECASE)
        if not slot_match:
            warnings.append(
                "templateHtml provided but slot placeholder not found; returning generated HTML only."
            )
            return body_html, warnings

        body_fragment, extracted = _extract_body_fragment(body_html)
        if extracted:
            warnings.append("Template mode: stripped outer <body> wrapper from model HTML before injection.")

        slot_html = slot_match.group(0)
        injected_slot = slot_html.replace("</div>", f"{body_fragment}</div>", 1)
        return template_html.replace(slot_html, injected_slot, 1), warnings

    body_fragment, extracted = _extract_body_fragment(body_html)
    if extracted:
        warnings.append("Template mode: stripped outer <body> wrapper from model HTML before injection.")

    return template_html.replace(placeholder, body_fragment), warnings


# -----------------------------
# Operations
# -----------------------------
def _op_compose_email(req: dict) -> Tuple[int, dict]:
    brand = _normalize_brand(req)
    if brand != "Dodo":
        return 400, {"error": "Only brand=Dodo is supported."}

    brief = (req.get("brief") or "").strip()
    if not brief and not req.get("normalizedBrief"):
        return 400, {"error": "Provide brief OR normalizedBrief."}

    use_kb = req.get("useKnowledgeBase")
    template_html = (req.get("templateHtml") or "").strip()
    template_slot_key = (req.get("templateSlotKey") or "").strip()
    template_slot_label = (req.get("templateSlotLabel") or "").strip()
    kb_id_override = (req.get("kbId") or "").strip()

    if kb_id_override:
        resolved_kb_id = kb_id_override
    else:
        if _truthy(use_kb):
            resolved_kb_id = (os.getenv("EMAIL_STYLE_KB_ID") or "").strip()
        else:
            resolved_kb_id = ""

    rag_results = _clamp_int(req.get("ragResults"), 5, 1, 10)

    rag_sources: List[dict] = []
    rag_warnings: List[str] = []

    sanitized_rc, rc_warnings = _sanitize_rag_context(req)
    rag_warnings.extend(rc_warnings)

    if sanitized_rc:
        rag_sources = _rag_sources_from_ragcontext(sanitized_rc)
    else:
        query_text = f"Dodo SFMC email style guidance for: {brief}"
        rag_sources, kb_warnings = _retrieve_style(resolved_kb_id, query_text, rag_results)
        rag_warnings.extend(kb_warnings)

    model_id = (req.get("modelId") or "").strip() or os.getenv(
        "BEDROCK_WRITER_MODEL_ID",
        "anthropic.claude-3-sonnet-20240229-v1:0",
    )

    max_tokens = _clamp_int(req.get("maxTokens"), 3600, 200, 4000)
    temperature = _clamp_float(req.get("temperature"), 0.4, 0.0, 1.0)

    prompt = _build_writer_prompt(req, rag_sources, template_html)

    try:
        txt = _invoke_claude(model_id, prompt, max_tokens=max_tokens, temperature=temperature).strip()
        logger.info("WRITER_RAW_LEN %d", len(txt))
        logger.info("WRITER_RAW_START %s", txt[:2000])
        logger.info("WRITER_RAW_END")
    except Exception as e:
        logger.exception("Bedrock InvokeModel failed")
        return 502, {
            "error": "Model invocation failed",
            "errorType": type(e).__name__,
            "message": str(e),
            "ragUsed": bool(rag_sources),
            "ragSources": rag_sources,
            "warnings": rag_warnings,
        }

    out = _extract_json_object(txt)
    if not out:
        return 500, {
            "error": "Writer output was not valid JSON",
            "ragUsed": bool(rag_sources),
            "ragSources": rag_sources,
            "warnings": rag_warnings + ["Writer output could not be parsed as JSON."],
        }

    subject = (out.get("subject") or "").strip()
    preheader = (out.get("preheader") or "").strip()
    html_field = (out.get("html") or "").strip()

    writer_warnings = out.get("warnings") or []
    if not isinstance(writer_warnings, list):
        writer_warnings = [str(writer_warnings)]

    html_plain, html_b64, model_returned_b64 = _as_html_plain_and_b64(html_field)

    return_b64 = _truthy(req.get("returnHtmlB64"))
    extra: List[str] = []
    if not model_returned_b64 and html_plain:
        extra.append("Writer returned raw HTML; normalized to base64 for safety.")
    if model_returned_b64 and html_field and re.search(r"\s", html_field):
        extra.append("Writer returned base64 with whitespace; whitespace stripped for decoding/safety.")

    template_warnings: List[str] = []
    if template_html:
        html_plain, template_warnings = _apply_template(
            template_html,
            html_plain,
            template_slot_key,
            template_slot_label,
        )
        html_b64 = base64.b64encode(html_plain.encode("utf-8")).decode("utf-8") if html_plain else ""

    max_html_chars = _clamp_int(os.getenv("MAX_HTML_CHARS", "200000"), 200000, 10000, 1000000)
    if html_plain and len(html_plain) > max_html_chars:
        return 500, {
            "error": "Writer returned oversized HTML",
            "message": f"HTML exceeded MAX_HTML_CHARS ({max_html_chars}).",
            "ragUsed": bool(rag_sources),
            "ragSources": rag_sources,
            "warnings": rag_warnings + writer_warnings + extra + template_warnings + ["HTML too large; ask the model to be more compact."],
        }

    html_out = html_b64 if return_b64 else html_plain

    if not subject or not html_out:
        return 500, {
            "error": "Writer returned incomplete output",
            "message": "subject and html are required.",
            "ragUsed": bool(rag_sources),
            "ragSources": rag_sources,
            "warnings": rag_warnings + writer_warnings + extra + template_warnings,
        }

    asset_name = (req.get("assetName") or req.get("name") or "").strip()
    folder_path = (req.get("folderPath") or "").strip()
    asset_type_name = (req.get("assetTypeName") or "htmlemail").strip() or "htmlemail"
    text_content = (out.get("textContent") or out.get("text") or "").strip()

    if not asset_name:
        extra.append("No assetName provided; emailBlueprint.name left empty.")
    if not folder_path:
        extra.append("No folderPath provided; emailBlueprint.folderPath left empty.")

    return 200, {
        "brand": "Dodo",
        "subject": subject,
        "preheader": preheader or "",
        "html": html_out,
        "htmlIsB64": bool(return_b64),
        "ragUsed": bool(rag_sources),
        "ragSources": rag_sources,
        "warnings": rag_warnings + writer_warnings + extra + template_warnings,
        "emailBlueprint": {
            "name": asset_name,
            "folderPath": folder_path,
            "assetTypeName": asset_type_name,
            "subject": subject,
            "preheader": preheader or "",
            "htmlContent": html_plain,
            "htmlContentB64": html_b64,
            **({"textContent": text_content} if text_content else {}),
            "ragUsed": bool(rag_sources),
            "ragSources": rag_sources,
            "warnings": rag_warnings + writer_warnings + extra + template_warnings,
        },
    }




# -----------------------------
# Lambda entry
# -----------------------------
def lambda_handler(event, context):
    api_path = _get_api_path(event)
    method = _get_http_method(event)

    is_bedrock = _is_bedrock_action_group_event(event)

    def respond(body_obj: Any, status: int) -> dict:
        return _bedrock_actiongroup_response(event, body_obj, http_code=status) if is_bedrock else _http_response(
            body_obj, http_code=status
        )

    if method != "POST":
        return respond({"error": "Only POST is supported."}, 405)

    req = _read_request_json(event) or {}

    try:
        p = (api_path or "").lower()

        if p == "/composeemail":
            status, out = _op_compose_email(req)
            return respond(out, status)

        return respond({"error": f"Unknown apiPath: {api_path}"}, 404)

    except Exception as e:
        logger.exception("Unhandled error")
        return respond({"error": "Unhandled exception", "errorType": type(e).__name__, "message": str(e)}, 500)
