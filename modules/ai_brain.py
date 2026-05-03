# modules/ai_brain.py
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx

from config.settings import OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "ai_brain"

# CONSTANTS

OPENROUTER_API_URL: str = os.environ.get(
    "OPENROUTER_API_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)
OPENROUTER_API_KEY: str = os.environ.get("OPENROUTER_API_KEY", "")
DEFAULT_MODEL: str = (
    os.environ.get("OPENROUTER_AI_MODEL")
    or os.environ.get("PHANTOM_AI_MODEL", "google/gemma-3-27b-it")
)

# Model fallback chain - tried in order if the primary fails
MODEL_FALLBACK_CHAIN: tuple[str, ...] = (
    "google/gemma-3-27b-it",
)

# Validated module names — AI cannot hallucinate modules outside this set
VALID_MODULES: frozenset[str] = frozenset({
    "subdomain_enum", "host_probe", "port_scanner", "tech_fingerprint",
    "wayback_harvest", "dir_bruteforce", "js_analyzer", "param_discovery",
    "xss_scanner", "xss_verifier", "sqli_scanner", "ssrf_redirect",
    "broken_auth_idor", "cve_lookup", "screenshot", "nuclei",
})

REQUEST_TIMEOUT_S: float = 90.0
MAX_RETRIES: int = 3
RETRY_BACKOFF_S: float = 2.0

MAX_TOKENS_DECISION: int = 1200
MAX_TOKENS_WRITEUP: int = 2500
MAX_TOKENS_TRIAGE: int = 1500
MAX_TOKENS_ESCALATION: int = 800

# Findings truncated to this char limit before sending to AI
MAX_FINDINGS_CHARS: int = 6000
MAX_SINGLE_FINDING_CHARS: int = 1500

# Severity scores for prioritization — higher = more urgent
SEVERITY_SCORES: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Severity thresholds that trigger immediate escalation
ESCALATION_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

# Finding types that always trigger immediate escalation
ESCALATION_TYPES: frozenset[str] = frozenset({
    "ssrf_confirmed", "chain_ssrf_cloud_metadata",
    "sqli_confirmed", "error_based", "time_based",
    "auth_bypass", "jwt_none", "mass_assignment",
    "idor_vertical",
})


# ENUMERATIONS
class AnalysisPhase(str, Enum):
    POST_RECON   = "post_recon"
    POST_SCAN    = "post_scan"
    ESCALATION   = "escalation"
    FINAL_TRIAGE = "final_triage"


# DATA MODELS
@dataclass
class ModulePriority:
    """
    AI decision about pipeline execution.
    Pipeline reads this to gate which modules actually run.
    """
    run_modules: list[str]
    skip_modules: list[str]
    focus_params: list[str]
    focus_paths: list[str]
    reasoning: str
    risk_level: str
    stealth_mode: bool  = False   # WAF detected → slow down
    exploit_mode: bool  = False   # Confirmed SQLi → run SQLMap deep
    alert: str | None  = None

    def should_run(self, module: str) -> bool:
        """
        Returns True if module should execute.
        If run_modules is empty → all modules run (no restriction).
        If module is explicitly in skip_modules → never runs.
        """
        if module in self.skip_modules:
            return False
        if not self.run_modules:
            return True
        return module in self.run_modules


@dataclass
class EscalationAlert:
    """Immediate escalation triggered by a critical mid-scan finding."""
    finding_type: str
    severity: str
    url: str
    parameter: str | None
    immediate_action: str         # What to do RIGHT NOW
    chain_potential: str         # How this chains to bigger impact
    cvss_estimate: float


@dataclass
class FindingWriteup:
    """HackerOne P1-quality bug bounty report for a single finding."""
    finding_id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str       # e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    summary: str
    vulnerability_type: str       # CWE reference
    steps_to_reproduce: list[str]
    poc_code: str       # Actual PoC — curl command or Python snippet
    impact: str
    attack_chain: str | None
    remediation: str
    remediation_code: str | None  # Actual fix example
    references: list[str]
    bounty_estimate: str
    confidence: str         # "confirmed" | "probable" | "possible"


@dataclass
class TriageResult:
    """Complete AI triage of all scan findings."""
    target: str
    risk_summary: str
    overall_risk: str           # "critical" | "high" | "medium" | "low"
    total_findings: int
    critical_count: int
    high_count: int
    attack_narrative: str           # Full attack chain story
    top_findings: list[dict[str, Any]]
    writeups: list[FindingWriteup]
    recommended_next: list[str]     # What to test manually


@dataclass
class ScanState:
    """
    Persistent state object carried through the entire pipeline.
    The AI brain writes decisions here.
    The pipeline reads from here to gate module execution.
    This is what makes the AI actually change scan behavior — not just log recommendations.
    """
    target: str
    decisions: list[ModulePriority] = field(default_factory=list)
    escalations: list[EscalationAlert] = field(default_factory=list)
    triage: TriageResult | None = None
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    model_used: str = DEFAULT_MODEL
    total_tokens: int = 0
    total_latency_ms: float = 0.0

    @property
    def latest_decision(self) -> ModulePriority | None:
        return self.decisions[-1] if self.decisions else None

    @property
    def is_stealth_mode(self) -> bool:
        return any(d.stealth_mode for d in self.decisions)

    @property
    def is_exploit_mode(self) -> bool:
        return any(d.exploit_mode for d in self.decisions)

    def should_run_module(self, module: str) -> bool:
        """
        Checks latest AI decision to determine if module should run.
        Falls back to True if no decision exists — safe default.
        """
        if not self.latest_decision:
            return True
        return self.latest_decision.should_run(module)

    def add_findings(self, findings: list[dict[str, Any]]) -> None:
        """Merges new findings into state, deduplicating by (url, type) key."""
        if not isinstance(findings, list):
            log.warning(f"[AI] add_findings expected list, got {type(findings).__name__}")
            return

        existing_keys: set[tuple[str, str]] = {
            (
                str(f.get("url", "")),
                str(f.get("finding_type") or f.get("technique") or "unknown"),
            )
            for f in self.all_findings
            if isinstance(f, dict)
        }
        for f in findings:
            if not isinstance(f, dict):
                log.warning(f"[AI] Skipping non-dict finding: {type(f).__name__}")
                continue
            key = (
                str(f.get("url", "")),
                str(f.get("finding_type") or f.get("technique") or "unknown"),
            )
            if key not in existing_keys:
                existing_keys.add(key)
                self.all_findings.append(f)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "model_used": self.model_used,
            "total_tokens": self.total_tokens,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "decisions_count": len(self.decisions),
            "escalations": [_to_dict(e) for e in self.escalations],
            "triage": _to_dict(self.triage),
            "findings_count": len(self.all_findings),
        }


# UTILITIES
def _to_dict(obj: Any) -> Any:
    """Recursively converts dataclass / list / primitive to dict."""
    if obj is None:
        return None
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in obj.__dict__.items()}
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    return obj


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated for token efficiency]"


def _findings_to_context(findings: list[dict[str, Any]]) -> str:
    """
    Converts findings to compact AI-readable context.
    Strips large evidence blobs — AI needs signal not HTTP responses.
    Sorts by severity score descending so AI sees the worst first.
    """
    if not isinstance(findings, list):
        log.warning(f"[AI] _findings_to_context expected list, got {type(findings).__name__}")
        return "[]"

    compact: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        compact.append({
            "type": str(f.get("finding_type") or f.get("technique") or f.get("type", "unknown")),
            "severity": str(f.get("severity", "unknown")),
            "url": str(f.get("url", "")),
            "parameter": str(f.get("parameter") or f.get("param") or ""),
            "database": f.get("database"),
            "confirmed": bool(f.get("is_confirmed") or f.get("executed") or f.get("oob_hit")),
            "chain": bool(f.get("chain") or f.get("chain_type") or f.get("chain_id")),
        })

    # Sort: confirmed critical findings first
    compact.sort(
        key=lambda x: (
            int(bool(x.get("confirmed"))),
            SEVERITY_SCORES.get(str(x.get("severity", "")).lower(), 0),
        ),
        reverse=True,
    )
    return _truncate(json.dumps(compact, indent=2), MAX_FINDINGS_CHARS)


def _tech_summary(tech_result: dict[str, Any] | None) -> str:
    """Extracts compact tech stack summary from fingerprint result dict."""
    if not tech_result or not isinstance(tech_result, dict):
        return "Stack: unknown | WAF: unknown"

    fps = tech_result.get("fingerprints", [])
    if not isinstance(fps, list):
        return "Stack: unknown | WAF: unknown"
    techs: set[str] = set()
    missing: set[str] = set()
    waf: str | None = None

    for fp in fps:
        if not isinstance(fp, dict):
            continue
        techs.update(fp.get("technologies", []))
        missing.update(fp.get("missing_headers", []))
        if fp.get("waf_detected") and not waf:
            waf = fp["waf_detected"]

    return (
        f"Stack: {', '.join(sorted(techs)) or 'unknown'}\n"
        f"WAF: {waf or 'none'}\n"
        f"Missing security headers: {', '.join(sorted(missing)) or 'none'}"
    )


def _needs_escalation(finding: dict[str, Any]) -> bool:
    """
    Returns True if finding warrants immediate AI escalation.
    Checks severity level and finding type.
    """
    if not isinstance(finding, dict):
        return False
    severity = str(finding.get("severity", "")).lower()
    finding_type = str(
        finding.get("finding_type") or finding.get("technique") or ""
    ).lower()

    return (
        severity in ESCALATION_SEVERITIES
        or finding_type in ESCALATION_TYPES
    )


def _validate_modules(raw: list[Any]) -> list[str]:
    """
    Validates AI-returned module list against VALID_MODULES allowlist.
    Prevents AI hallucination from injecting invalid module names.
    """
    if not isinstance(raw, list):
        log.warning(f"[AI] _validate_modules expected list, got {type(raw).__name__}")
        return []
    return [str(m) for m in raw if str(m) in VALID_MODULES]


# OPENROUTER CLIENT
class OpenRouterClient:
    """
    Sync OpenRouter API client with model fallback and retry logic.
    Context manager — always close after use.
    """

    def __init__(
        self,
        api_key: str = OPENROUTER_API_KEY,
        model: str = DEFAULT_MODEL,
    ) -> None:
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY not set. "
                "Run: export OPENROUTER_API_KEY=sk-or-..."
            )
        self._api_key = api_key
        self._model = model
        self._client = httpx.Client(
            timeout=REQUEST_TIMEOUT_S,
            verify=True,  # Always verify TLS to the AI API provider
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://phantom-vapt.local",
                "X-Title": "PHANTOM VAPT Framework",
            },
        )

    def __enter__(self) -> OpenRouterClient:
        return self

    def __exit__(self, *_: object) -> None:
        self._client.close()

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int   = MAX_TOKENS_DECISION,
        temperature: float = 0.15,
    ) -> tuple[str, str, int]:
        """
        Sends chat completion. Returns (response_text, model_used, tokens_used).
        Tries MODEL_FALLBACK_CHAIN on 4xx/5xx errors.
        Raises RuntimeError only if ALL models fail.
        """
        models = [self._model] + [m for m in MODEL_FALLBACK_CHAIN if m != self._model]
        last_error: Exception | None = None

        for model in models:
            for attempt in range(MAX_RETRIES):
                try:
                    resp = self._client.post(
                        OPENROUTER_API_URL,
                        json={
                            "model": model,
                            "max_tokens": max_tokens,
                            "temperature": temperature,
                            "messages": [
                                {"role": "system", "content": system_prompt},
                                {"role": "user",   "content": user_prompt},
                            ],
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise RuntimeError("No choices in API response")
                    content = choices[0].get("message", {}).get("content", "").strip()
                    if not content:
                        raise RuntimeError("Empty response content")
                    tokens_used = data.get("usage", {}).get("total_tokens", 0)
                    return content, model, tokens_used

                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    if status == 429:
                        wait = RETRY_BACKOFF_S * (attempt + 1)
                        log.warning(f"[AI] Rate limited ({model}) — sleeping {wait}s")
                        time.sleep(wait)
                        continue
                    # 400/422 = model rejected request → try next model immediately
                    if status in (400, 422):
                        log.warning(f"[AI] {model} rejected ({status}) — trying next")
                        last_error = exc
                        break
                    last_error = exc
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_BACKOFF_S ** attempt)

                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    log.warning(f"[AI] Network error ({model}): {type(exc).__name__}")
                    last_error = exc
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_BACKOFF_S ** attempt)

        raise RuntimeError(f"All AI models exhausted. Last error: {last_error}")


# PROMPT TEMPLATES
_SYSTEM_PROMPT: str = """
You are an elite bug bounty hunter and penetration tester.
10+ years experience. HackerOne Hall of Fame. Hundreds of P1 reports filed.
You think like an attacker, write like a senior security engineer.
You are concise, precise, ruthlessly actionable.
No filler. No disclaimers. No markdown. Return only valid JSON unless told otherwise.
"""


_DECISION_PROMPT: str = """VAPT scan in progress for {target}.

PHASE: {phase}
TECH STACK:
{tech_context}

FINDINGS SO FAR ({count} total):
{findings_context}

AVAILABLE MODULES: {available_modules}

Respond with this exact JSON:
{{
  "run_modules": ["module_name"],
  "skip_modules": ["module_name"],
  "focus_params": ["id", "user"],
  "focus_paths": ["/admin", "/api/v1"],
  "risk_level": "critical|high|medium|low",
  "stealth_mode": false,
  "exploit_mode": false,
  "reasoning": "Single paragraph. Attacker mindset. What is the fastest path to a P1?",
  "alert": "Immediate critical observation or null"
}}

Rules:
- Only use modules from AVAILABLE MODULES list
- stealth_mode=true if WAF detected — slow scan, rotate UAs
- exploit_mode=true if SQLi confirmed — authorize deep SQLMap run
- focus_params: highest-priority injection points based on findings
- If SSRF confirmed: flag immediately in alert, focus on cloud metadata chain
- Return valid JSON only"""


_ESCALATION_PROMPT: str = """CRITICAL FINDING during live scan of {target}.

FINDING:
{finding_json}

CURRENT SCAN STATE:
{state_context}

Respond with this exact JSON:
{{
  "immediate_action": "Exact next step to take RIGHT NOW (specific command or test)",
  "chain_potential": "How this finding chains to bigger impact — be specific",
  "cvss_estimate": 8.5,
  "stop_scan": false,
  "escalate_to_exploit": false,
  "notes": "Any critical observation about this specific finding"
}}

Be aggressive. Be specific. What would you do right now if you found this on a bug bounty?"""


_WRITEUP_PROMPT: str = """Write a P1 HackerOne bug bounty report for this vulnerability.

TARGET: {target}
FINDING:
{finding_json}

Return this exact JSON (all fields required):
{{
  "finding_id": "{finding_id}",
  "title": "Specific, impactful title — not generic",
  "severity": "critical|high|medium|low",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "vulnerability_type": "CWE-89: SQL Injection",
  "summary": "2-3 sentences. What is it, where is it, what can attacker do.",
  "steps_to_reproduce": [
    "1. Navigate to https://target.com/...",
    "2. Set parameter X to ...",
    "3. Observe response contains ..."
  ],
  "poc_code": "curl -s 'https://target.com/api?id=1 OR 1=1--' | jq .  # or Python snippet",
  "impact": "Specific data/access impact. Name what tables, what accounts, what systems.",
  "attack_chain": "How this combines with other findings for full compromise or null",
  "remediation": "Specific fix — not 'use parameterized queries' but HOW exactly",
  "remediation_code": "# Python/PHP/JS example of correct implementation or null",
  "references": ["https://owasp.org/...", "https://cwe.mitre.org/data/definitions/89.html"],
  "bounty_estimate": "$2000-$5000 (P1 on most programs)",
  "confidence": "confirmed|probable|possible"
}}"""


_TRIAGE_PROMPT: str = """Final triage of complete VAPT scan for {target}.

ALL FINDINGS ({count} total):
{findings_context}

TECH STACK:
{tech_context}

Return this exact JSON:
{{
  "risk_summary": "3-4 sentences. Board-level executive summary of risk posture.",
  "overall_risk": "critical|high|medium|low",
  "critical_count": 0,
  "high_count": 0,
  "attack_narrative": "Tell the full attack story. How would a real attacker move from initial access to full compromise using these findings? Name specific URLs, params, chains. 4-6 sentences.",
  "top_findings": [
    {{
      "rank": 1,
      "type": "finding_type",
      "url": "url",
      "severity": "critical",
      "why_top": "Why this is the highest-impact finding"
    }}
  ],
  "recommended_next": [
    "Manual test X at URL Y because Z",
    "Check for Y vulnerability because tech stack suggests susceptibility"
  ]
}}"""


# JSON PARSER

def _parse_json(raw: str, context: str) -> dict[str, Any]:
    """
    Parses AI response as JSON. Strips markdown fences.
    Raises ValueError with context on failure — never silently passes.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError(f"AI returned empty/invalid response [{context}]")

    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines   = cleaned.split("\n")
        end_idx = next((i for i, l in enumerate(lines[1:], 1) if l.strip() == "```"), -1)
        cleaned = "\n".join(lines[1:end_idx] if end_idx > 0 else lines[1:])
    if not cleaned:
        raise ValueError(f"AI returned empty JSON after stripping markdown [{context}]")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"AI returned invalid JSON [{context}]: {exc}\nRaw (first 400): {raw[:400]}"
        ) from exc


#CORE PROCESSORS
def _process_decision(
    client: OpenRouterClient,
    target: str,
    phase: AnalysisPhase,
    findings: list[dict[str, Any]],
    tech_result: dict[str, Any] | None,
    available: list[str],
) -> tuple[ModulePriority, str, int]:
    """
    Sends scan state to AI, receives and validates module priority decision.
    Returns (ModulePriority, model_used, tokens_used).
    """
    prompt = _DECISION_PROMPT.format(
        target=target,
        phase=phase.value,
        tech_context=_tech_summary(tech_result),
        findings_context=_findings_to_context(findings),
        count=len(findings),
        available_modules=", ".join(available),
    )

    raw, model, tokens = client.complete(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=prompt,
        max_tokens=MAX_TOKENS_DECISION,
        temperature=0.10,
    )

    data = _parse_json(raw, f"decision:{phase.value}")
    if not isinstance(data, dict):
        raise ValueError(f"AI decision response not a dict: {type(data)}")

    decision = ModulePriority(
        run_modules=_validate_modules(data.get("run_modules", [])),
        skip_modules=_validate_modules(data.get("skip_modules", [])),
        focus_params=data.get("focus_params", []),
        focus_paths=data.get("focus_paths", []),
        reasoning=data.get("reasoning", ""),
        risk_level=data.get("risk_level", "medium"),
        stealth_mode=bool(data.get("stealth_mode", False)),
        exploit_mode=bool(data.get("exploit_mode", False)),
        alert=data.get("alert"),
    )

    log.info(f"[AI] Decision — run={decision.run_modules} skip={decision.skip_modules}")
    log.info(f"[AI] Risk={decision.risk_level} stealth={decision.stealth_mode} exploit={decision.exploit_mode}")
    if decision.alert:
        log.warning(f"[AI] ★ ALERT: {decision.alert}")

    return decision, model, tokens


def _process_escalation(
    client: OpenRouterClient,
    target: str,
    finding: dict[str, Any],
    state: ScanState,
) -> tuple[EscalationAlert, str, int]:
    """
    Immediate AI analysis of a critical finding mid-scan.
    Returns actionable escalation alert.
    """
    state_context = (
        f"Findings so far: {len(state.all_findings)} | "
        f"Stealth: {state.is_stealth_mode} | "
        f"Exploit mode: {state.is_exploit_mode}"
    )

    prompt = _ESCALATION_PROMPT.format(
        target=target,
        finding_json=_truncate(json.dumps(finding, indent=2), MAX_SINGLE_FINDING_CHARS),
        state_context=state_context,
    )

    raw, model, tokens = client.complete(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=prompt,
        max_tokens=MAX_TOKENS_ESCALATION,
        temperature=0.10,
    )

    data = _parse_json(raw, f"escalation:{finding.get('finding_type', 'unknown')}")
    if not isinstance(data, dict):
        raise ValueError(f"AI escalation response not a dict: {type(data)}")

    alert = EscalationAlert(
        finding_type=str(finding.get("finding_type") or finding.get("technique", "unknown")),
        severity=str(finding.get("severity", "high")),
        url=str(finding.get("url", "")),
        parameter=finding.get("parameter"),
        immediate_action=data.get("immediate_action", ""),
        chain_potential=data.get("chain_potential", ""),
        cvss_estimate=float(data.get("cvss_estimate", 7.5)),
    )

    log.warning(
        f"[AI] ★ ESCALATION [{alert.finding_type}] CVSS≈{alert.cvss_estimate}\n"
        f"     Action: {alert.immediate_action}\n"
        f"     Chain:  {alert.chain_potential}"
    )
    return alert, model, tokens


def _process_writeup(
    client:  OpenRouterClient,
    target:  str,
    finding: dict[str, Any],
) -> FindingWriteup | None:
    """
    Generates P1-quality HackerOne writeup for a single finding.
    Returns None on parse failure — non-blocking.
    """
    finding_id = str(finding.get("id") or finding.get("url", "finding"))[:50]

    prompt = _WRITEUP_PROMPT.format(
        target=target,
        finding_json=_truncate(json.dumps(finding, indent=2), MAX_SINGLE_FINDING_CHARS),
        finding_id=finding_id,
    )

    try:
        raw, _, tokens = client.complete(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=prompt,
            max_tokens=MAX_TOKENS_WRITEUP,
            temperature=0.20,
        )
        data = _parse_json(raw, f"writeup:{finding_id}")
        if not isinstance(data, dict):
            raise ValueError(f"Writeup response not a dict: {type(data)}")
    except (ValueError, RuntimeError) as exc:
        log.warning(f"[AI] Writeup failed for {finding_id}: {exc}")
        return None

    return FindingWriteup(
        finding_id=finding_id,
        title=data.get("title", "Untitled Finding"),
        severity=data.get("severity", "medium"),
        cvss_score=float(data.get("cvss_score", 5.0)),
        cvss_vector=data.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
        vulnerability_type=data.get("vulnerability_type", "CWE-unknown"),
        summary=data.get("summary", ""),
        steps_to_reproduce=data.get("steps_to_reproduce", []),
        poc_code=data.get("poc_code", ""),
        impact=data.get("impact", ""),
        attack_chain=data.get("attack_chain"),
        remediation=data.get("remediation", ""),
        remediation_code=data.get("remediation_code"),
        references=data.get("references", []),
        bounty_estimate=data.get("bounty_estimate", "Unknown"),
        confidence=data.get("confidence", "possible"),
    )


def _process_triage(
    client: OpenRouterClient,
    target: str,
    findings: list[dict[str, Any]],
    tech_result: dict[str, Any] | None,
) -> TriageResult:
    """
    Full triage of all scan findings.
    Generates writeups for top 5 findings sorted by severity.
    """
    # Sort findings by severity for writeup prioritization
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_SCORES.get(str(f.get("severity", "")).lower(), 0),
        reverse=True,
    )

    prompt = _TRIAGE_PROMPT.format(
        target=target,
        count=len(findings),
        findings_context=_findings_to_context(findings),
        tech_context=_tech_summary(tech_result),
    )

    raw, _, _ = client.complete(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=prompt,
        max_tokens=MAX_TOKENS_TRIAGE,
        temperature=0.10,
    )

    data = _parse_json(raw, "triage")
    if not isinstance(data, dict):
        raise ValueError(f"AI triage response not a dict: {type(data)}")

    # Generate writeups for top 5 confirmed/highest-severity findings
    top_for_writeup = [
        f for f in sorted_findings
        if f.get("is_confirmed") or f.get("executed") or f.get("oob_hit")
    ][:5] or sorted_findings[:5]

    writeups: list[FindingWriteup] = []
    for finding in top_for_writeup:
        writeup = _process_writeup(client, target, finding)
        if writeup:
            writeups.append(writeup)
            log.info(f"[AI] Writeup: [{writeup.severity.upper()}] {writeup.title[:70]}")

    return TriageResult(
        target=target,
        risk_summary=data.get("risk_summary", ""),
        overall_risk=data.get("overall_risk", "unknown"),
        total_findings=len(findings),
        critical_count=int(data.get("critical_count", 0)),
        high_count=int(data.get("high_count", 0)),
        attack_narrative=data.get("attack_narrative", ""),
        top_findings=data.get("top_findings", []),
        writeups=writeups,
        recommended_next=data.get("recommended_next", []),
    )


# SAVE
def _save_state(state: ScanState) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe     = safe_filename(state.target)
    out_file = OUTPUT_PATH / f"{safe}_brain_state.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(state.to_dict(), f, indent=2)
    log.info(f"[AI] State saved → {out_file}")
    return out_file


def _save_writeups(state: ScanState) -> Path | None:
    if not state.triage or not state.triage.writeups:
        return None
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe     = safe_filename(state.target)
    out_file = OUTPUT_PATH / f"{safe}_writeups.json"
    writeups_data = [_to_dict(w) for w in state.triage.writeups]
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(writeups_data, f, indent=2)
    log.info(f"[AI] Writeups saved → {out_file}")
    return out_file


# PUBLIC API

def create_scan_state(target: str) -> ScanState:
    """
    Creates a fresh ScanState for a new scan.
    Pass this through the entire pipeline — every module feeds it, brain reads it.
    """
    if not target:
        raise ValueError("Target cannot be empty")
    return ScanState(target=target)


def ai_decision(
    state: ScanState,
    phase: AnalysisPhase,
    tech_result: dict[str, Any] | None = None,
    available_modules: list[str] | None = None,
    model:str = DEFAULT_MODEL,
) -> ScanState:
    """
    AI pipeline decision engine.
    Reads current ScanState, returns updated ScanState with new ModulePriority.

    The pipeline reads state.should_run_module(name) before executing each module.
    This is what makes the AI actually gate execution — not just recommend.

    Args:
        state:             Current scan state (carries all findings).
        phase:             Which scan phase just completed.
        tech_result:       TechScanResult.to_dict() from Step 9.
        available_modules: Modules available to run next.
        model:             OpenRouter model string.
    """
    section(f"AI Decision [{phase.value}] → {state.target}")

    if not OPENROUTER_API_KEY:
        log.warning("[AI] OPENROUTER_API_KEY not set — AI decisions disabled")
        return state

    available = available_modules or sorted(VALID_MODULES)
    t_start   = time.monotonic()

    try:
        with OpenRouterClient(model=model) as client:
            decision, model_used, tokens = _process_decision(
                client, state.target, phase,
                state.all_findings, tech_result, available,
            )
        state.decisions.append(decision)
        state.model_used = model_used
        state.total_tokens += tokens
        state.total_latency_ms += (time.monotonic() - t_start) * 1000
    except (RuntimeError, ValueError) as exc:
        log.error(f"[AI] Decision failed: {exc}")

    _save_state(state)
    return state


def ai_escalate(
    state: ScanState,
    finding: dict[str, Any],
    model: str = DEFAULT_MODEL,
) -> ScanState:
    """
    Immediate AI escalation triggered by a critical mid-scan finding.
    Call this as soon as a critical finding is confirmed — don't wait for phase end.

    The pipeline calls this automatically when _needs_escalation(finding) is True.

    Args:
        state:   Current scan state.
        finding: The critical finding dict that triggered escalation.
        model:   OpenRouter model string.
    """
    if not OPENROUTER_API_KEY:
        return state

    if not _needs_escalation(finding):
        return state

    log.warning(
        f"[AI] ★ ESCALATION TRIGGERED — "
        f"{finding.get('finding_type', 'unknown')} at {finding.get('url', '')}"
    )
    t_start = time.monotonic()

    try:
        with OpenRouterClient(model=model) as client:
            alert, model_used, tokens = _process_escalation(
                client, state.target, finding, state,
            )
        state.escalations.append(alert)
        state.model_used = model_used
        state.total_tokens += tokens
        state.total_latency_ms += (time.monotonic() - t_start) * 1000
    except (RuntimeError, ValueError) as exc:
        log.error(f"[AI] Escalation failed: {exc}")

    _save_state(state)
    return state


def ai_triage(
    state: ScanState,
    tech_result: dict[str, Any] | None = None,
    model: str = DEFAULT_MODEL,
) -> ScanState:
    """
    Final AI triage after all scanning is complete.
    Generates risk summary, attack narrative, and P1-quality writeups for top findings.
    Updates state.triage in place.

    Args:
        state:       Complete scan state with all findings.
        tech_result: TechScanResult.to_dict() from Step 9.
        model:       OpenRouter model string.
    """
    section(f"AI Triage → {state.target}")

    if not OPENROUTER_API_KEY:
        log.warning("[AI] OPENROUTER_API_KEY not set — AI triage disabled")
        return state

    if not state.all_findings:
        log.info("[AI] No findings to triage")
        return state

    log.info(f"[AI] Triaging {len(state.all_findings)} findings")
    t_start = time.monotonic()

    try:
        with OpenRouterClient(model=model) as client:
            triage = _process_triage(
                client, state.target, state.all_findings, tech_result
            )
        state.triage            = triage
        state.total_latency_ms += (time.monotonic() - t_start) * 1000
    except (RuntimeError, ValueError) as exc:
        log.error(f"[AI] Triage failed: {exc}")
        _save_state(state)
        return state

    log.info(f"[AI] Risk: {state.triage.overall_risk.upper()} — {state.triage.risk_summary[:100]}")
    log.info(f"[AI] Attack narrative: {state.triage.attack_narrative[:120]}")
    log.info(f"[AI] Writeups: {len(state.triage.writeups)}")

    if state.triage.recommended_next:
        log.info("[AI] Recommended manual tests:")
        for rec in state.triage.recommended_next:
            log.info(f"  → {rec}")

    _save_state(state)
    _save_writeups(state)
    return state


def check_and_escalate(
    state: ScanState,
    findings: list[dict[str, Any]],
    model: str = DEFAULT_MODEL,
) -> ScanState:
    """
    Checks a batch of new findings for escalation triggers.
    Fires ai_escalate() immediately for each critical finding.
    Call this after every module completes — not just at phase boundaries.

    Args:
        state:    Current scan state.
        findings: New findings from the module that just ran.
        model:    OpenRouter model string.
    """
    if not isinstance(findings, list):
        log.warning(f"[AI] check_and_escalate expected list, got {type(findings).__name__}")
        return state

    state.add_findings(findings)

    for finding in findings:
        if _needs_escalation(finding):
            state = ai_escalate(state, finding, model)

    return state