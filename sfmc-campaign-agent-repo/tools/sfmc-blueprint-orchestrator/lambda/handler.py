# sfmc-blueprint-orchestrator/lambda_function.py
import os
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# -----------------------------
# Env / Guardrails
# -----------------------------
OUTPUT_SCHEMA_VERSION = str(os.getenv("OUTPUT_SCHEMA_VERSION", "1.0")).strip() or "1.0"

BLUEPRINT_ONLY = str(os.getenv("BLUEPRINT_ONLY", "true")).strip().lower() in ("true", "1", "yes", "y")
SANDBOX_ONLY = str(os.getenv("SANDBOX_ONLY", "true")).strip().lower() in ("true", "1", "yes", "y")

SUMMARY_TEXT_TRUNCATE = int(os.getenv("SUMMARY_TEXT_TRUNCATE", "800"))

MAX_BLUEPRINT_ASSETS = int(os.getenv("MAX_BLUEPRINT_ASSETS", "25"))
MAX_BLUEPRINT_DATA_EXTENSIONS = int(os.getenv("MAX_BLUEPRINT_DATA_EXTENSIONS", "15"))
MAX_BLUEPRINT_JOURNEYS = int(os.getenv("MAX_BLUEPRINT_JOURNEYS", "5"))
MAX_BLUEPRINT_AUTOMATIONS = int(os.getenv("MAX_BLUEPRINT_AUTOMATIONS", "10"))

DEFAULT_FOLDER_ROOT = (os.getenv("DEFAULT_FOLDER_ROOT", "Generate_Via_AI_Agent") or "Generate_Via_AI_Agent").strip().strip("/")
DEFAULT_EMAIL_FOLDER = (os.getenv("DEFAULT_EMAIL_FOLDER", f"{DEFAULT_FOLDER_ROOT}/Emails") or f"{DEFAULT_FOLDER_ROOT}/Emails").strip().strip("/")
DEFAULT_JOURNEY_FOLDER = (os.getenv("DEFAULT_JOURNEY_FOLDER", f"{DEFAULT_FOLDER_ROOT}/Journeys") or f"{DEFAULT_FOLDER_ROOT}/Journeys").strip().strip("/")
DEFAULT_AUTOMATION_FOLDER = (os.getenv("DEFAULT_AUTOMATION_FOLDER", f"{DEFAULT_FOLDER_ROOT}/Automations") or f"{DEFAULT_FOLDER_ROOT}/Automations").strip().strip("/")
DEFAULT_DE_FOLDER = (os.getenv("DEFAULT_DE_FOLDER", f"{DEFAULT_FOLDER_ROOT}/DataExtensions") or f"{DEFAULT_FOLDER_ROOT}/DataExtensions").strip().strip("/")

# -----------------------------
# Helpers: HTTP-ish responses
# -----------------------------
def _json_response(body_obj: dict, status_code: int = 200) -> dict:
    return {
        "statusCode": status_code,
        "body": json.dumps(body_obj),
        "headers": {"Content-Type": "application/json"},
    }

def _truncate(s: Any, max_len: int = SUMMARY_TEXT_TRUNCATE) -> Any:
    if s is None:
        return None
    if not isinstance(s, str):
        return s
    return s if len(s) <= max_len else (s[:max_len] + "…")

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

# -----------------------------
# Blueprint generation (heuristic, deterministic)
# -----------------------------
_SECTION_RE = re.compile(
    r"(?mi)^\s*(goal|objective|audience|offer|incentive|timing|schedule|channels?|constraints?)\s*:\s*(.+?)\s*$"
)

def _parse_sections(brief: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not brief:
        return out
    for m in _SECTION_RE.finditer(brief):
        k = (m.group(1) or "").strip().lower()
        v = (m.group(2) or "").strip()
        if k and v:
            out[k] = v
    return out

def _infer_channels(brief: str, explicit: Optional[List[str]]) -> List[str]:
    if isinstance(explicit, list) and explicit:
        ch = []
        for x in explicit:
            s = str(x).strip().lower()
            if s:
                ch.append(s)
        return sorted(list(dict.fromkeys(ch)))  # stable-ish dedupe
    b = (brief or "").lower()
    found = []
    if "sms" in b or "text message" in b:
        found.append("sms")
    if "push" in b or "notification" in b:
        found.append("push")
    if "direct mail" in b or "letter" in b:
        found.append("directmail")
    # email default
    if "email" in b or not found:
        found.append("email")
    return sorted(list(dict.fromkeys(found)))

def _safe_folder(path: str) -> str:
    p = (path or "").strip().strip("/")
    if not p:
        return DEFAULT_FOLDER_ROOT
    # enforce sandbox root
    if SANDBOX_ONLY:
        if not (p == DEFAULT_FOLDER_ROOT or p.startswith(DEFAULT_FOLDER_ROOT + "/")):
            p = f"{DEFAULT_FOLDER_ROOT}/{p}"
    return p

def _slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "campaign"

def _make_de_fields(channels: List[str]) -> List[dict]:
    # conservative baseline schema for orchestration
    fields = [
        {"name": "SubscriberKey", "type": "Text", "length": 50, "isPrimaryKey": True, "isNullable": False},
        {"name": "EmailAddress", "type": "EmailAddress", "length": 254, "isPrimaryKey": False, "isNullable": True},
        {"name": "FirstName", "type": "Text", "length": 50, "isPrimaryKey": False, "isNullable": True},
        {"name": "Segment", "type": "Text", "length": 100, "isPrimaryKey": False, "isNullable": True},
        {"name": "EligibilityFlag", "type": "Boolean", "isPrimaryKey": False, "isNullable": True},
    ]
    if "sms" in channels:
        fields.append({"name": "MobileNumber", "type": "Phone", "length": 30, "isPrimaryKey": False, "isNullable": True})
    return fields

def generate_blueprint(params: Dict[str, Any]) -> Tuple[dict, List[str]]:
    warnings: List[str] = []

    brief = params.get("brief")
    normalized_brief = params.get("normalizedBrief")
    if not brief and not normalized_brief:
        raise ValueError("Provide brief OR normalizedBrief")

    # If normalizedBrief is an object, keep it; if string, treat as brief.
    normalized_obj: Optional[dict] = None
    if isinstance(normalized_brief, dict):
        normalized_obj = normalized_brief
    elif isinstance(normalized_brief, str) and normalized_brief.strip():
        brief = normalized_brief

    brief_text = str(brief or "").strip()
    sections = _parse_sections(brief_text)

    campaign_name = (params.get("campaignName") or "").strip()
    if not campaign_name:
        # try from normalized brief
        if normalized_obj and isinstance(normalized_obj.get("campaignName"), str):
            campaign_name = normalized_obj.get("campaignName").strip()
    if not campaign_name:
        # heuristic from first line
        first_line = brief_text.splitlines()[0].strip() if brief_text else ""
        campaign_name = first_line[:80] if first_line else "Campaign Blueprint"

    channels = _infer_channels(brief_text, params.get("channels") if isinstance(params.get("channels"), list) else None)

    objective = sections.get("goal") or sections.get("objective") or (normalized_obj.get("objective") if normalized_obj else None) or ""
    audience = sections.get("audience") or (normalized_obj.get("audience") if normalized_obj else None) or ""
    offer = sections.get("offer") or sections.get("incentive") or (normalized_obj.get("offer") if normalized_obj else None) or ""
    timing = sections.get("timing") or sections.get("schedule") or (normalized_obj.get("timing") if normalized_obj else None) or ""

    constraints = params.get("constraints") if isinstance(params.get("constraints"), dict) else (normalized_obj.get("constraints") if normalized_obj else {})
    if not isinstance(constraints, dict):
        constraints = {}

    include_rationale = bool(params.get("includeRationale", False))

    # folders
    folders = {
        "root": _safe_folder(params.get("folderRoot") or DEFAULT_FOLDER_ROOT),
        "emails": _safe_folder(params.get("emailFolder") or DEFAULT_EMAIL_FOLDER),
        "journeys": _safe_folder(params.get("journeyFolder") or DEFAULT_JOURNEY_FOLDER),
        "automations": _safe_folder(params.get("automationFolder") or DEFAULT_AUTOMATION_FOLDER),
        "dataExtensions": _safe_folder(params.get("deFolder") or DEFAULT_DE_FOLDER),
    }

    # assets (conservative defaults)
    assets: List[dict] = []
    base_slug = _slug(campaign_name)

    def _add_asset(a: dict):
        if len(assets) >= MAX_BLUEPRINT_ASSETS:
            warnings.append(f"Asset cap reached ({MAX_BLUEPRINT_ASSETS}); truncating assets.")
            return
        assets.append(a)

    if "email" in channels:
        _add_asset({
            "type": "email",
            "name": f"{campaign_name} - Email 01",
            "folderPath": folders["emails"],
            "subject": f"{campaign_name}",
            "preheader": "Short supporting line here",
            "copyBrief": _truncate(f"Objective: {objective}\nOffer: {offer}\nAudience: {audience}", 600),
            "audienceRule": _truncate(audience, 200) or "Define audience segment in DE / query.",
            "keyHint": f"{base_slug}_email_01"
        })
        # If timing suggests follow-up OR multiple touches mentioned, add reminder
        if re.search(r"remind|follow|day\s*2|day\s*3|second|nudge|if no", brief_text.lower()):
            _add_asset({
                "type": "email",
                "name": f"{campaign_name} - Email 02 Reminder",
                "folderPath": folders["emails"],
                "subject": f"Reminder: {campaign_name}",
                "preheader": "Quick reminder preheader",
                "copyBrief": _truncate("Reminder / nudge variant. Reference prior message, reinforce offer, add urgency.", 600),
                "audienceRule": "Subset: did not click/open OR did not convert (define tracking rule).",
                "keyHint": f"{base_slug}_email_02"
            })

    if "sms" in channels:
        _add_asset({
            "type": "sms",
            "name": f"{campaign_name} - SMS 01",
            "folderPath": folders["emails"],  # if you store SMS content elsewhere, change env + default
            "copyBrief": _truncate(f"Short SMS aligned to: {objective}. Offer: {offer}. Include link placeholder.", 400),
            "audienceRule": _truncate(audience, 200) or "Define SMS-eligible audience (has MobileNumber + consent).",
            "keyHint": f"{base_slug}_sms_01"
        })

    # data extensions (1 primary send DE; more if requested)
    des: List[dict] = []
    if len(des) < MAX_BLUEPRINT_DATA_EXTENSIONS:
        des.append({
            "name": f"{campaign_name} - Send Audience",
            "customerKey": f"{base_slug}_send_audience",
            "folderPath": folders["dataExtensions"],
            "fields": _make_de_fields(channels),
            "populationHint": _truncate(
                "Populate via Query Activity (preferred) or Data Extension filter/export/import pipeline. "
                "Include exclusions from constraints.",
                600
            ),
        })
    else:
        warnings.append(f"DE cap reached ({MAX_BLUEPRINT_DATA_EXTENSIONS}); no DEs created.")

    # journeys (only if multi-step implied)
    journeys: List[dict] = []
    journey_needed = ("sms" in channels) or ("push" in channels) or re.search(r"journey|wait|decision|if no", brief_text.lower())
    if journey_needed and len(journeys) < MAX_BLUEPRINT_JOURNEYS:
        steps = [
            {"type": "entry", "name": "Entry", "hint": "Entry from Send Audience DE (or entry event)."},
            {"type": "send", "name": "Send Email 01", "hint": "Use Email 01 asset."},
        ]
        if re.search(r"day\s*2|48\s*hour|wait", brief_text.lower()):
            steps.append({"type": "wait", "name": "Wait", "hint": "Wait 2 days (or as per timing)."})
        steps.append({"type": "decision", "name": "Decision", "hint": "Branch on click/conversion (define data source)."})
        if "sms" in channels:
            steps.append({"type": "send", "name": "Send SMS 01", "hint": "Send to non-converters / non-clickers."})
        journeys.append({
            "name": f"{campaign_name} - Journey",
            "folderPath": folders["journeys"],
            "entrySourceHint": "DE Entry: Send Audience (or event-based entry if available).",
            "steps": steps
        })
    elif journey_needed:
        warnings.append(f"Journey cap reached ({MAX_BLUEPRINT_JOURNEYS}); journey omitted.")

    # automations (outline only)
    automations: List[dict] = []
    automation_needed = True  # generally needed to build/refresh DE
    if automation_needed and len(automations) < MAX_BLUEPRINT_AUTOMATIONS:
        steps = [
            {"type": "sqlQuery", "name": "Build Send Audience DE", "hint": "Query Activity to populate send DE."}
        ]
        if isinstance(constraints, dict) and constraints.get("exclusions"):
            steps.append({"type": "sqlQuery", "name": "Apply Exclusions", "hint": "Exclude suppression segments per constraints."})
        automations.append({
            "name": f"{campaign_name} - Audience Refresh",
            "folderPath": folders["automations"],
            "scheduleHint": timing or "On-demand / scheduled as required (e.g., daily 9am).",
            "steps": steps
        })
    elif automation_needed:
        warnings.append(f"Automation cap reached ({MAX_BLUEPRINT_AUTOMATIONS}); automation omitted.")

    # execution plan (downstream tools)
    execution_plan = [
        {"step": 1, "tool": "sfmc-de-schema-designer", "description": "Confirm DE schema(s) for the campaign audience and tracking."},
        {"step": 2, "tool": "sfmc-de-creator", "description": "Create DE(s) in sandbox folder structure."},
        {"step": 3, "tool": "sfmc-query-designer", "description": "Design Query Activity(ies) to populate audience DE(s)."},
        {"step": 4, "tool": "sfmc-automation-draft-creator", "description": "Create Automation draft for audience refresh (read-only/draft mode)."},
    ]
    if any(a.get("type") == "email" for a in assets):
        execution_plan.append({"step": len(execution_plan)+1, "tool": "sfmc-email-composer", "description": "Draft email HTML/content from copy brief."})
        execution_plan.append({"step": len(execution_plan)+1, "tool": "sfmc-email-asset-writer", "description": "Create Email asset(s) in Content Builder (sandbox folders)."})
    if journeys:
        execution_plan.append({"step": len(execution_plan)+1, "tool": "sfmc-journey-draft-creator", "description": "Create Journey draft aligned to blueprint steps."})

    out = {
        "schemaVersion": OUTPUT_SCHEMA_VERSION,
        "campaign": {
            "name": campaign_name,
            "objective": _truncate(objective, 400),
            "audience": _truncate(audience, 400),
            "offer": _truncate(offer, 400),
            "timing": _truncate(timing, 400),
            "channels": channels,
        },
        "constraints": constraints,
        "folders": folders,
        "assets": assets,
        "dataExtensions": des,
        "journeys": journeys,
        "automations": automations,
        "executionPlan": execution_plan,
    }

    if include_rationale:
        out["rationale"] = _truncate(
            "Heuristic blueprint generated from provided brief. Review and adjust before executing build tools. "
            "No SFMC IDs are assumed; downstream tools should resolve/create assets safely in sandbox folders.",
            800
        )

    if BLUEPRINT_ONLY is False:
        warnings.append("WARNING: BLUEPRINT_ONLY env var is false. This tool is intended to be blueprint-only.")

    return out, warnings

# -----------------------------
# Blueprint validation
# -----------------------------
def validate_blueprint(bp: Dict[str, Any]) -> Tuple[dict, List[str], List[str]]:
    warnings: List[str] = []
    errors: List[str] = []

    if not isinstance(bp, dict):
        return {"valid": False, "errors": ["blueprint must be an object"], "warnings": []}, [], ["blueprint must be an object"]

    # required top-level
    for k in ["schemaVersion", "campaign", "folders"]:
        if k not in bp:
            errors.append(f"Missing required field: {k}")

    folders = bp.get("folders") if isinstance(bp.get("folders"), dict) else {}
    root = str(folders.get("root") or DEFAULT_FOLDER_ROOT).strip().strip("/")

    # sandbox folder enforcement
    if SANDBOX_ONLY:
        if not root or root != DEFAULT_FOLDER_ROOT:
            # allow custom root if it still starts with DEFAULT_FOLDER_ROOT (but root itself should be default)
            if not (root == DEFAULT_FOLDER_ROOT or root.startswith(DEFAULT_FOLDER_ROOT + "/")):
                errors.append(f"folders.root must be under '{DEFAULT_FOLDER_ROOT}' when SANDBOX_ONLY=true")
        for fk in ["emails", "journeys", "automations", "dataExtensions"]:
            p = str(folders.get(fk) or "").strip().strip("/")
            if p and not (p == DEFAULT_FOLDER_ROOT or p.startswith(DEFAULT_FOLDER_ROOT + "/")):
                errors.append(f"folders.{fk} must be under '{DEFAULT_FOLDER_ROOT}' when SANDBOX_ONLY=true")

    # caps
    def _cap_check(name: str, arr: Any, cap: int):
        if isinstance(arr, list) and len(arr) > cap:
            errors.append(f"{name} exceeds cap ({len(arr)} > {cap})")

    _cap_check("assets", bp.get("assets"), MAX_BLUEPRINT_ASSETS)
    _cap_check("dataExtensions", bp.get("dataExtensions"), MAX_BLUEPRINT_DATA_EXTENSIONS)
    _cap_check("journeys", bp.get("journeys"), MAX_BLUEPRINT_JOURNEYS)
    _cap_check("automations", bp.get("automations"), MAX_BLUEPRINT_AUTOMATIONS)

    # DE schema sanity
    des = bp.get("dataExtensions") if isinstance(bp.get("dataExtensions"), list) else []
    for i, de in enumerate(des):
        if not isinstance(de, dict):
            errors.append(f"dataExtensions[{i}] must be an object")
            continue
        if not str(de.get("name") or "").strip():
            errors.append(f"dataExtensions[{i}].name is required")
        if not str(de.get("customerKey") or "").strip():
            errors.append(f"dataExtensions[{i}].customerKey is required")
        fields = de.get("fields")
        if not isinstance(fields, list) or not fields:
            errors.append(f"dataExtensions[{i}].fields must be a non-empty array")

    # execution plan sanity
    ep = bp.get("executionPlan") if isinstance(bp.get("executionPlan"), list) else []
    for i, step in enumerate(ep):
        if not isinstance(step, dict):
            warnings.append(f"executionPlan[{i}] is not an object")
            continue
        if not str(step.get("tool") or "").strip():
            warnings.append(f"executionPlan[{i}].tool missing")

    valid = len(errors) == 0
    result = {"valid": valid, "errors": errors, "warnings": warnings}
    return result, warnings, errors

# -----------------------------
# Handlers
# -----------------------------
def _handle_generate_blueprint(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        bp, warnings = generate_blueprint(params)
        return 200, {
            "ok": True,
            "tool": "blueprint_orchestrator_generate",
            "input": params,
            "output": bp,
            "warnings": warnings
        }
    except Exception as e:
        logger.exception("generateBlueprint failed")
        return 500, {"ok": False, "error": str(e)}

def _handle_validate_blueprint(params: Dict[str, Any]) -> Tuple[int, dict]:
    try:
        bp = params.get("blueprint")
        if not isinstance(bp, dict):
            return 400, {"ok": False, "error": "blueprint (object) is required"}
        res, warnings, errors = validate_blueprint(bp)
        return 200, {
            "ok": True,
            "tool": "blueprint_orchestrator_validate",
            "input": {"blueprintProvided": True},
            "output": res,
            "warnings": warnings,
            "errors": errors
        }
    except Exception as e:
        logger.exception("validateBlueprint failed")
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
        logger.info("Parsed Bedrock params keys: %s", list(params.keys()))

        if api_path in ("/generateblueprint", "/getblueprint", "/blueprint"):
            status, body = _handle_generate_blueprint(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        if api_path in ("/validateblueprint", "/blueprintvalidate"):
            status, body = _handle_validate_blueprint(params)
            return _bedrock_actiongroup_response(event, body, http_code=status)

        return _bedrock_actiongroup_response(
            event,
            {"ok": False, "error": f"Unknown apiPath: {api_path}"},
            http_code=400
        )

    # Direct invoke (API Gateway-style)
    body_in = event.get("body")
    try:
        params = json.loads(body_in) if isinstance(body_in, str) else (body_in or {})
    except Exception:
        params = {}

    path = _get_api_path(event).lower()

    if path in ("/generateblueprint", "/getblueprint", "/blueprint"):
        status, body = _handle_generate_blueprint(params)
        return _json_response(body, status)

    if path in ("/validateblueprint", "/blueprintvalidate"):
        status, body = _handle_validate_blueprint(params)
        return _json_response(body, status)

    return _json_response({"ok": False, "error": f"Unknown path: {path}"}, 400)
