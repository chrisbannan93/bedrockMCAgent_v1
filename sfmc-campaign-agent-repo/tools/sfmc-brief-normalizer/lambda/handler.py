import os
import json
import logging
import re
from typing import Any, Dict, Optional, Tuple

import boto3

# -------------------------------------------------
# Logging setup
# -------------------------------------------------
logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

DEBUG_EVENT = (os.getenv("DEBUG_EVENT", "false").strip().lower() == "true")

# -------------------------------------------------
# Bedrock runtime client
# -------------------------------------------------
BEDROCK_REGION = (os.getenv("BEDROCK_REGION") or "").strip()
if BEDROCK_REGION:
    bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
else:
    bedrock = boto3.client("bedrock-runtime")

BRIEF_MODEL_ID = (os.getenv("BRIEF_MODEL_ID") or "").strip()

# -------------------------------------------------
# Generic HTTP / JSON helpers
# -------------------------------------------------
def _json_response(body_obj: dict, status_code: int = 200) -> dict:
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }

# -------------------------------------------------
# Bedrock Agent event helpers
# -------------------------------------------------
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

def _is_bedrock_event(event: dict) -> bool:
    return isinstance(event, dict) and "messageVersion" in event and "response" not in event

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
        s = (val or "").strip()
        try:
            return json.loads(s)
        except Exception:
            return [x.strip() for x in s.split(",") if x.strip()]
    return val

def _parse_bedrock_params(event: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    agi = event.get("actionGroupInvocationInput", {}) or {}
    base = agi if agi else event

    plist = base.get("parameters") or []
    if isinstance(plist, list):
        for p in plist:
            name = p.get("name")
            if not name:
                continue
            out[name] = _coerce_typed_value(p.get("type"), p.get("value"))

    rb = base.get("requestBody") or {}
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        if isinstance(content, dict):
            aj = content.get("application/json") or content.get("application_json") or {}

            if isinstance(aj, dict) and isinstance(aj.get("properties"), list):
                for it in aj["properties"]:
                    name = it.get("name")
                    if not name:
                        continue
                    out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            elif isinstance(aj, list):
                for it in aj:
                    name = it.get("name")
                    if not name:
                        continue
                    out[name] = _coerce_typed_value(it.get("type"), it.get("value"))
            elif isinstance(aj, dict) and "body" in aj:
                body = aj.get("body")
                if isinstance(body, dict):
                    out.update(body)
                elif isinstance(body, str):
                    try:
                        parsed = json.loads(body)
                        if isinstance(parsed, dict):
                            out.update(parsed)
                    except Exception:
                        pass

    if isinstance(rb, dict) and "body" in rb:
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

    logger.info("Extracted Bedrock params keys: %s", list(out.keys()))
    return out

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

# -------------------------------------------------
# Brief normalization helpers
# -------------------------------------------------
REQUIRED_FIELDS = ["campaignName", "businessObjective", "primaryChannels"]

def _strip_code_fences(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines)
    return t.strip()

def _extract_first_json_object(text: str) -> Optional[str]:
    """
    Best-effort: if the model returns extra prose, try to extract the first JSON object.
    This is intentionally conservative (handles the common "Sure, here's the JSON: {...}" case).
    """
    if not text:
        return None

    s = text.strip()
    if s.startswith("{") and s.endswith("}"):
        return s

    # Find first '{' and try to match until its corresponding closing '}' via a simple brace counter.
    start = s.find("{")
    if start < 0:
        return None

    depth = 0
    for i in range(start, len(s)):
        ch = s[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = s[start:i + 1].strip()
                return candidate

    return None

def _validate_normalized_brief(nb: dict) -> Optional[str]:
    if not isinstance(nb, dict):
        return "normalizedBrief must be an object"

    for field in REQUIRED_FIELDS:
        if field not in nb or nb[field] in ("", None):
            return f"normalizedBrief.{field} is required"

    pc = nb.get("primaryChannels")
    if not isinstance(pc, list):
        return "normalizedBrief.primaryChannels must be an array of strings"

    # Ensure array of strings (not objects/ints/etc.)
    if any((not isinstance(x, str) or not x.strip()) for x in pc):
        return "normalizedBrief.primaryChannels must be an array of non-empty strings"

    return None

def _fallback_brief(raw_brief: str, reason: str) -> dict:
    return {
        "normalizedBrief": {
            "campaignName": "Unknown",
            "businessObjective": (raw_brief or "")[:200],
            "primaryChannels": [],
            "secondaryChannels": [],
            "triggers": [],
            "targetSegments": [],
            "exclusions": [],
            "keyMessages": [],
            "offers": [],
            "journeyType": "Unknown",
            "lifecycleStage": "Unknown",
            "kpis": [],
            "constraints": [],
            "markets": [],
            "timing": {"start": None, "end": None, "cadence": None},
            "dependencies": [],
            "approvalsRequired": [],
            "risks": [],
            "notes": []
        },
        "warnings": [
            "Model returned invalid or unparsable JSON; fallback brief structure used.",
            reason
        ]
    }

def _call_bedrock_brief_model(raw_brief: str, context: Optional[dict]) -> dict:
    if not BRIEF_MODEL_ID:
        raise RuntimeError("BRIEF_MODEL_ID environment variable is not set")

    logger.info(
        "Calling Bedrock Converse with modelId=%s region=%s",
        BRIEF_MODEL_ID,
        BEDROCK_REGION or "(default)"
    )

    system_prompt = (
        "You are an internal campaign brief normalizer for Salesforce Marketing Cloud (SFMC).\n"
        "You MUST output ONE valid JSON object and NOTHING else.\n"
        "No markdown. No code fences. No preamble. No trailing commentary.\n"
        "The JSON MUST have exactly two top-level keys: normalizedBrief and warnings.\n"
        "warnings MUST be an array (can be empty).\n"
        "normalizedBrief MUST be an object and MUST include these required fields:\n"
        "- campaignName (string)\n"
        "- businessObjective (string)\n"
        "- primaryChannels (array of strings)\n"
        "If ambiguous/missing info: keep keys present with empty arrays/nulls and add explanations to warnings.\n"
        "Output must start with '{' and end with '}'.\n"
        "Example shape: {\"normalizedBrief\":{\"campaignName\":\"\",\"businessObjective\":\"\",\"primaryChannels\":[]},\"warnings\":[]}\n"
    )

    payload_text = {"rawBrief": raw_brief, "context": context or {}}

    # IMPORTANT: Converse content blocks are a tagged union: use {"text": "..."} only.
    messages = [
        {
            "role": "user",
            "content": [
                {"text": json.dumps(payload_text)}
            ],
        }
    ]

    response = bedrock.converse(
        modelId=BRIEF_MODEL_ID,
        system=[{"text": system_prompt}],
        messages=messages,
        inferenceConfig={
            "maxTokens": 900,
            "temperature": 0.0,
            "stopSequences": ["```"]
        },
    )

    try:
        msg = response["output"]["message"]
        contents = msg.get("content") or []

        # IMPORTANT: response content blocks are also tagged unions; text blocks contain a "text" key.
        text_parts = []
        for c in contents:
            if isinstance(c, dict) and "text" in c:
                text_parts.append(c.get("text") or "")

        raw_out = "\n".join(text_parts).strip()
    except Exception as e:
        logger.exception("Failed to extract text from Bedrock response")
        raise RuntimeError(f"Failed to extract model output: {e}")

    cleaned = _strip_code_fences(raw_out)

    # First try strict JSON parse
    try:
        parsed = json.loads(cleaned)
    except Exception:
        # Try best-effort extraction of first JSON object
        candidate = _extract_first_json_object(cleaned)
        if candidate:
            try:
                parsed = json.loads(candidate)
            except Exception as e2:
                logger.error("Model returned invalid JSON after extraction attempt.")
                return _fallback_brief(raw_brief, f"JSON parse error after extraction: {str(e2)}")
        else:
            logger.error("Model returned invalid JSON. raw_out=%s", raw_out)
            return _fallback_brief(raw_brief, "JSON parse error: unable to locate a JSON object in output")

    if not isinstance(parsed, dict) or "normalizedBrief" not in parsed:
        return _fallback_brief(raw_brief, "Model JSON missing 'normalizedBrief' at top level")

    nb = parsed.get("normalizedBrief")
    err = _validate_normalized_brief(nb)
    if err:
        return _fallback_brief(raw_brief, err)

    if "warnings" not in parsed or not isinstance(parsed["warnings"], list):
        parsed["warnings"] = []

    # Ensure exactly the two top-level keys (optional strictness)
    # If you want to enforce this, uncomment:
    # parsed = {"normalizedBrief": parsed.get("normalizedBrief"), "warnings": parsed.get("warnings", [])}

    return parsed

def _handle_normalize_brief(params: Dict[str, Any]) -> Tuple[int, dict]:
    raw_brief = params.get("rawBrief") or params.get("brief") or params.get("text")
    if not raw_brief or not str(raw_brief).strip():
        return 400, {"ok": False, "error": "rawBrief is required and must be non-empty"}

    context = params.get("context")
    if isinstance(context, str):
        try:
            parsed_ctx = json.loads(context)
            if isinstance(parsed_ctx, dict):
                context = parsed_ctx
        except Exception:
            pass

    try:
        result = _call_bedrock_brief_model(
            str(raw_brief),
            context if isinstance(context, dict) else None
        )

        warnings = result.get("warnings", [])
        if not isinstance(warnings, list):
            warnings = [str(warnings)]

        return 200, {
            "ok": True,
            "tool": "brief_normalizer",
            "input": {
                "rawBriefPreview": str(raw_brief)[:300],
                "contextProvided": isinstance(context, dict),
            },
            "output": {
                "normalizedBrief": result.get("normalizedBrief", {})
            },
            "warnings": warnings
        }

    except Exception as e:
        logger.exception("normalizeBrief failed")
        return 500, {"ok": False, "error": str(e)}

def lambda_handler(event, context):
    if DEBUG_EVENT:
        try:
            logger.info("RAW_EVENT_TYPE=%s", type(event))
            logger.info("RAW_EVENT_KEYS=%s", list(event.keys()) if isinstance(event, dict) else "NOT_A_DICT")
            if isinstance(event, dict):
                logger.info("RAW_EVENT_SAMPLE=%s", json.dumps(event)[:800])
        except Exception:
            logger.exception("Failed to log raw event")

    if isinstance(event, dict):
        path = _get_api_path(event)
        if path.lower() == "/health":
            return _json_response({"status": "ok", "service": "sfmc-brief-normalizer", "version": "1.1"}, 200)

    if isinstance(event, dict) and _is_bedrock_event(event):
        api_path = _get_api_path(event)
        params = _parse_bedrock_params(event)

        if api_path.lower() == "/normalizebrief":
            status, body = _handle_normalize_brief(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        body = {"ok": False, "error": f"Unknown apiPath for brief normalizer: {api_path}"}
        return _bedrock_actiongroup_response(event, body, http_code=400)

    if isinstance(event, dict):
        path = _get_api_path(event)
        body_in = event.get("body")
        try:
            if isinstance(body_in, str):
                params = json.loads(body_in)
            elif isinstance(body_in, dict):
                params = body_in
            elif body_in is None:
                params = event
            else:
                params = {}
        except Exception:
            params = {}

        if path.lower() == "/normalizebrief" or not path:
            status, body = _handle_normalize_brief(params)
            return _json_response(body, status)

        if path.lower() == "/health":
            return _json_response({"status": "ok", "service": "sfmc-brief-normalizer", "version": "1.1"}, 200)

        return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)

    return _json_response({"ok": False, "error": "Unsupported event shape"}, 400)
