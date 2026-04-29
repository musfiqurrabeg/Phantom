from __future__ import annotations

import asyncio
import random
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.logger import get_logger
from modules.host_probe import ProbeResult
from modules.js_analyzer import JSAnalysisResult
from modules.param_discovery import ParamScanResult

log = get_logger()

# Constants
DEFAULT_TIMEOUT: float = 15.0
MAX_CONCURRENT: int = 20
MAX_TARGET_QUEUE: int = 200
RESPONSE_BODY_PREVIEW: int = 400
IDOR_LENGTH_TOLERANCE: int = 50
STEALTH_MIN_DELAY: float = 0.3
STEALTH_MAX_DELAY: float = 1.5

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0",
]

IDOR_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:user|account|profile|id|uid|pid|oid|object)=([0-9a-f\-]{4,})", re.I),
    re.compile(
        r"/(?:api/v\d+/)?(?:users?|accounts?|profiles?|orders?|items?|documents?)/([0-9a-f\-]{4,})",
        re.I,
    ),
    re.compile(r"[?&](?:[^&]*[._\-]?id[^&]*=)([0-9]{1,12})", re.I),
]

_NUMERIC_RE: re.Pattern[str] = re.compile(r"/(\d{1,12})(?=/|$|\?)")
_UUID_RE: re.Pattern[str] = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)

AUTH_BYPASS_HEADERS: list[dict[str, str]] = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Authorization": "null"},
    {"Authorization": "undefined"},
    {"X-HTTP-Method-Override": "GET"},
]

# JWT with alg:none — header.payload. (empty signature)
JWT_NONE_TOKEN: str = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    "."
)

ADMIN_KEYWORDS: frozenset[str] = frozenset({
    "admin", "manage", "delete", "config", "settings", "superuser", "root",
})
AUTH_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "auth", "oauth", "token", "session",
})

SESSION_EXPOSURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'"user(?:name|_?id|_?email)":\s*"[^"]+"', re.I),
    re.compile(r'"role":\s*"(?:admin|superuser|root)"', re.I),
    re.compile(r'"(?:access|auth)_token":\s*"[A-Za-z0-9._\-]+"', re.I),
    re.compile(r"<(?:h[1-6]|title)[^>]*>.*?(?:dashboard|admin\s+panel|account)", re.I),
]

# Sentinel value used to detect enum-vs-string at runtime (see B4 note)
_CRITICAL_STR: str = "critical"
_HIGH_STR: str = "high"


# Enums

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    IDOR_HORIZONTAL = "idor_horizontal"
    IDOR_VERTICAL = "idor_vertical"
    AUTH_BYPASS = "auth_bypass"
    JWT_NONE = "jwt_none"
    SESSION_EXPOSURE = "session_exposure"
    PRIV_ESCALATION = "priv_escalation"


# Models

class AuthFinding(BaseModel):
    # use_enum_values=True → pydantic stores plain str on fields typed as Enum
    # So f.severity == "critical" (str), NOT Severity.CRITICAL (enum)
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: secrets.token_hex(8))
    target: str
    url: str
    finding_type: FindingType
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    chain_source: str | None = None

    @field_validator("confidence")
    @classmethod
    def round_confidence(cls, v: float) -> float:
        return round(v, 2)


@dataclass(slots=True)
class AuthScanResult:
    target: str
    findings: list[AuthFinding] = field(default_factory=list)
    tested_endpoints: int = 0
    confirmed_vulns: int = 0
    chain_opportunities: list[dict[str, Any]] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == _CRITICAL_STR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.model_dump() for f in self.findings],
            "summary": {
                "tested": self.tested_endpoints,
                "confirmed": self.confirmed_vulns,
                "critical": self.critical_count,
                "chains": len(self.chain_opportunities),
            },
        }


# URL helpers

def _has_id_pattern(url: str) -> bool:
    return any(pat.search(url) for pat in IDOR_URL_PATTERNS)


def _looks_like_jwt_url(url: str) -> bool:
    return bool(re.search(r"[=\/]eyJ[a-zA-Z0-9_\-]*\.eyJ", url)) or any(
        kw in url.lower() for kw in AUTH_KEYWORDS
    )


def _mutate_id_in_url(url: str) -> tuple[str, str] | None:
    """
    Return (original_id, mutated_url) with the first mutable ID incremented.

    B1: Uses str.replace on the matched span text instead of re.sub with
    backreferences — avoids the group(2) empty-match edge case entirely.
    """
    # Numeric path segment: /42 → /43
    match = _NUMERIC_RE.search(url)
    if match:
        original = match.group(1)
        mutated = str(int(original) + 1)
        old_segment = f"/{original}"
        new_segment = f"/{mutated}"
        idx = match.start()
        return original, url[:idx] + new_segment + url[idx + len(old_segment):]

    # UUID path segment: last 4 hex chars incremented
    match = _UUID_RE.search(url)
    if match:
        original = match.group(1)
        prefix, last = original[:-4], original[-4:]
        try:
            last_int = int(last, 16)
            if last_int >= 0xFFFF:
                return None  # overflow — skip rather than wrap to 0000
            mutated = prefix + format(last_int + 1, "04x")
            return original, url.replace(original, mutated, 1)
        except ValueError:
            return None

    # Query parameter: ?user_id=7 → ?user_id=8
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, values in qs.items():
        if "id" in key.lower() and values and values[0].isdigit():
            original = values[0]
            qs[key] = [str(int(original) + 1)]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            return original, parsed._replace(query=new_query).geturl()

    return None


def _join_url(base: str, path: str) -> str:
    """
    Join base URL with path safely.
    Absolute paths (/foo) replace only the path component of base.
    Relative paths (foo) are joined normally.
    """
    if not path:
        return base
    if path.startswith("/"):
        parsed = urllib.parse.urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else base
        return urllib.parse.urljoin(root, path)
    return urllib.parse.urljoin(base, path)


def _host_to_base_url(host: object) -> str:
    """
    Convert a live_hosts entry to a full base URL string.

    B9: typed as object — narrows correctly for str vs HostInfo-like objects.
    """
    if isinstance(host, str):
        if host.startswith(("http://", "https://")):
            return host
        return f"https://{host}"

    hostname: str = (
        getattr(host, "hostname", None)
        or getattr(host, "host", None)
        or str(host)
    )
    port: int | None = getattr(host, "port", None)
    scheme = "http" if port == 80 else "https"
    if port and port not in (80, 443):
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def _extract_cookies(resp: httpx.Response) -> str | None:
    """
    Combine all Set-Cookie headers into a single Cookie header string.
    Strips cookie attributes (Path, HttpOnly, etc.) — keeps name=value only.
    """
    set_cookie_headers = resp.headers.get_list("set-cookie")
    if not set_cookie_headers:
        return None
    cookies = [cookie_str.split(";")[0].strip() for cookie_str in set_cookie_headers]
    non_empty = [c for c in cookies if c]
    return "; ".join(non_empty) if non_empty else None


def _body_has_session_exposure(body: str) -> bool:
    if not body:
        return False
    return any(pat.search(body[:4096]) for pat in SESSION_EXPOSURE_PATTERNS)


def _random_ua() -> str:
    return random.choice(USER_AGENTS)


# HTTP helper
async def _get(
    client: httpx.AsyncClient,
    url: str,
    extra_headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    stealth: bool = False,
) -> httpx.Response | None:
    if stealth:
        await asyncio.sleep(random.uniform(STEALTH_MIN_DELAY, STEALTH_MAX_DELAY))  # noqa: S311
    headers = {"User-Agent": _random_ua(), **(extra_headers or {})}
    try:
        return await client.get(url, headers=headers, follow_redirects=follow_redirects)
    except httpx.TimeoutException:
        log.debug(f"[AuthScan] Timeout: {url}")
    except httpx.RequestError as exc:
        log.debug(f"[AuthScan] RequestError: {url} — {exc}")
    return None


# IDORScanner

class IDORScanner:
    """Horizontal and vertical IDOR detection."""

    def __init__(self, target: str, sem: asyncio.Semaphore, stealth: bool = False) -> None:
        self._target = target
        self._sem = sem
        self._stealth = stealth

    async def scan(
        self, client: httpx.AsyncClient, urls: list[str]
    ) -> list[AuthFinding]:
        tasks = [asyncio.create_task(self._probe(client, url)) for url in urls]
        batches = await asyncio.gather(*tasks)
        return [f for batch in batches for f in batch]

    async def _probe(
        self, client: httpx.AsyncClient, url: str
    ) -> list[AuthFinding]:
        findings: list[AuthFinding] = []
        h = await self._test_horizontal(client, url)
        if h:
            findings.append(h)
        v = await self._test_vertical(client, url)
        if v:
            findings.append(v)
        return findings

    async def _test_horizontal(
        self, client: httpx.AsyncClient, url: str
    ) -> AuthFinding | None:
        if not _has_id_pattern(url):
            return None

        mutation = _mutate_id_in_url(url)
        if mutation is None:
            return None
        original_id, test_url = mutation

        async with self._sem:
            baseline = await _get(client, url, stealth=self._stealth)
        if not baseline or baseline.status_code >= 400:
            return None

        async with self._sem:
            resp = await _get(client, test_url, stealth=self._stealth)
        if not resp:
            return None

        same_status = resp.status_code == baseline.status_code
        both_success = 200 <= resp.status_code < 300
        length_similar = abs(len(resp.text) - len(baseline.text)) < IDOR_LENGTH_TOLERANCE
        content_differs = resp.text.strip() != baseline.text.strip()

        if same_status and both_success and length_similar and content_differs:
            return AuthFinding(
                target=self._target,
                url=test_url,
                finding_type=FindingType.IDOR_HORIZONTAL,
                severity=Severity.HIGH,
                title="Horizontal IDOR: Resource accessible via ID manipulation",
                description=(
                    f"Incrementing ID `{original_id}` returned a different valid resource "
                    f"(HTTP {resp.status_code}, "
                    f"Δ{abs(len(resp.text) - len(baseline.text))}B)"
                ),
                evidence={
                    "original_id": original_id,
                    "tested_url": test_url,
                    "baseline_status": baseline.status_code,
                    "test_status": resp.status_code,
                    "length_delta": abs(len(resp.text) - len(baseline.text)),
                },
                remediation=(
                    "Enforce server-side ownership checks on every resource request. "
                    "Never rely on client-supplied IDs alone."
                ),
                confidence=0.88,
                chain_source="param_discovery",
            )
        return None

    async def _test_vertical(
        self, client: httpx.AsyncClient, url: str
    ) -> AuthFinding | None:
        if not any(kw in url.lower() for kw in ADMIN_KEYWORDS):
            return None

        async with self._sem:
            resp = await _get(
                client,
                url,
                extra_headers={"Cookie": "", "Authorization": ""},
                follow_redirects=False,
                stealth=self._stealth,
            )
        if not resp or resp.status_code != 200:
            return None

        if any(kw in resp.text.lower() for kw in ADMIN_KEYWORDS):
            return AuthFinding(
                target=self._target,
                url=url,
                finding_type=FindingType.IDOR_VERTICAL,
                severity=Severity.CRITICAL,
                title="Vertical IDOR: Admin endpoint accessible without privileges",
                description=(
                    "Unauthenticated GET to admin-scoped endpoint "
                    "returned HTTP 200 with admin content."
                ),
                evidence={
                    "status_code": resp.status_code,
                    "snippet": resp.text[:RESPONSE_BODY_PREVIEW],
                },
                remediation=(
                    "Enforce RBAC on all admin endpoints. "
                    "Return 401/403 for unauthenticated/unauthorised requests."
                ),
                confidence=0.92,
            )
        return None


# AuthScanner
class AuthScanner:
    """Auth bypass, JWT none algorithm, and session exposure detection."""

    def __init__(self, target: str, sem: asyncio.Semaphore, stealth: bool = False) -> None:
        self._target = target
        self._sem = sem
        self._stealth = stealth

    async def scan(
        self, client: httpx.AsyncClient, urls: list[str]
    ) -> list[AuthFinding]:
        tasks = [asyncio.create_task(self._probe(client, url)) for url in urls]
        batches = await asyncio.gather(*tasks)
        return [f for batch in batches for f in batch]

    async def _probe(
        self, client: httpx.AsyncClient, url: str
    ) -> list[AuthFinding]:
        findings: list[AuthFinding] = []
        findings.extend(await self._test_auth_bypass(client, url))
        jwt = await self._test_jwt_none(client, url)
        if jwt:
            findings.append(jwt)
        session = await self._test_session_exposure(client, url)
        if session:
            findings.append(session)
        return findings

    async def _test_auth_bypass(
        self, client: httpx.AsyncClient, url: str
    ) -> list[AuthFinding]:
        async with self._sem:
            baseline = await _get(
                client, url, follow_redirects=False, stealth=self._stealth
            )
        if not baseline or baseline.status_code not in (401, 403):
            return []

        findings: list[AuthFinding] = []
        for bypass_headers in AUTH_BYPASS_HEADERS:
            async with self._sem:
                resp = await _get(
                    client,
                    url,
                    extra_headers=bypass_headers,
                    follow_redirects=False,
                    stealth=self._stealth,
                )
            if resp and resp.status_code == 200:
                header_key = next(iter(bypass_headers))
                findings.append(AuthFinding(
                    target=self._target,
                    url=url,
                    finding_type=FindingType.AUTH_BYPASS,
                    severity=Severity.CRITICAL,
                    title=f"Auth Bypass via Header: {header_key}",
                    description=(
                        f"Injecting `{header_key}: {bypass_headers[header_key]}` "
                        f"bypassed HTTP {baseline.status_code} → 200"
                    ),
                    evidence={
                        "bypass_header": bypass_headers,
                        "baseline_status": baseline.status_code,
                        "bypass_status": resp.status_code,
                    },
                    remediation=(
                        "Never use client-supplied headers for access control. "
                        "Validate auth server-side on every request."
                    ),
                    confidence=0.98,
                ))
        return findings

    async def _test_jwt_none(
        self, client: httpx.AsyncClient, url: str
    ) -> AuthFinding | None:
        if not _looks_like_jwt_url(url):
            return None

        async with self._sem:
            resp = await _get(
                client,
                url,
                extra_headers={"Authorization": f"Bearer {JWT_NONE_TOKEN}"},
                stealth=self._stealth,
            )
        if resp and resp.status_code == 200:
            return AuthFinding(
                target=self._target,
                url=url,
                finding_type=FindingType.JWT_NONE,
                severity=Severity.CRITICAL,
                title="JWT 'none' Algorithm Accepted",
                description=(
                    "Server accepted an unsigned JWT (alg:none), allowing arbitrary "
                    "identity claims without signature verification."
                ),
                evidence={
                    "token_prefix": JWT_NONE_TOKEN[:60] + "...",
                    "status_code": resp.status_code,
                },
                remediation=(
                    "Reject JWTs with 'none' algorithm unconditionally. "
                    "Enforce RS256 or ES256 with key pinning."
                ),
                confidence=1.0,
            )
        return None

    async def _test_session_exposure(
        self, client: httpx.AsyncClient, url: str
    ) -> AuthFinding | None:
        if not any(kw in url.lower() for kw in AUTH_KEYWORDS):
            return None

        async with self._sem:
            resp = await _get(client, url, stealth=self._stealth)
        if not resp:
            return None

        session_cookie = _extract_cookies(resp)
        if not session_cookie:
            return None

        profile_url = _join_url(url, "/profile")

        async with self._sem:
            resp2 = await _get(
                client,
                profile_url,
                extra_headers={"Cookie": session_cookie},
                stealth=self._stealth,
            )
        if not resp2 or resp2.status_code != 200:
            return None

        if not _body_has_session_exposure(resp2.text):
            return None

        return AuthFinding(
            target=self._target,
            url=url,
            finding_type=FindingType.SESSION_EXPOSURE,
            severity=Severity.MEDIUM,
            title="Session Exposes Sensitive User Data",
            description=(
                "Session cookie from login endpoint grants access to sensitive "
                "user data on /profile without re-validation."
            ),
            evidence={
                "cookie_snippet": session_cookie[:80] + "...",
                "profile_status": resp2.status_code,
                "body_snippet": resp2.text[:RESPONSE_BODY_PREVIEW],
            },
            remediation=(
                "Bind sessions to IP/User-Agent. Regenerate session ID after login. "
                "Scope sensitive responses to authenticated+authorised users only."
            ),
            confidence=0.78,
        )


# Target queue builder
def _build_target_queue(
    target: str,
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None,
) -> list[str]:
    candidates: set[str] = set()
    for url in param_result.injectable_urls:
        if not isinstance(url, str):
            raise TypeError(
                f"param_result.injectable_urls must be list[str], "
                f"got element of type {type(url).__name__}"
            )
        if _has_id_pattern(url) or any(
            kw in url.lower() for kw in ADMIN_KEYWORDS | AUTH_KEYWORDS
        ):
            candidates.add(url)

    if js_result:
        target_base = f"https://{target}" if not target.startswith("http") else target
        for endpoint in js_result.all_endpoints:
            full = _join_url(target_base, endpoint)
            if _has_id_pattern(full) or any(
                kw in endpoint.lower() for kw in ADMIN_KEYWORDS | AUTH_KEYWORDS
            ):
                candidates.add(full)

    for host in probe_result.live_hosts:
        base = _host_to_base_url(host)
        for path in (
            "/api/user",
            "/profile",
            "/account/settings",
            "/admin/users",
            "/api/v1/me",
        ):
            candidates.add(_join_url(base, path))

    result = sorted(candidates)
    if len(result) > MAX_TARGET_QUEUE:
        log.warning(
            f"[AuthScan] Target queue truncated: {len(result)} → {MAX_TARGET_QUEUE}"
        )
    return result[:MAX_TARGET_QUEUE]


# Orchestrator
async def _run_scan(
    target: str,
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None,
    timeout: float,
    stealth: bool,
) -> AuthScanResult:
    urls = _build_target_queue(target, probe_result, param_result, js_result)
    if not urls:
        log.warning(f"[AuthScan] No testable endpoints found for {target}")
        return AuthScanResult(target=target)

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    idor_scanner = IDORScanner(target, sem, stealth)
    auth_scanner = AuthScanner(target, sem, stealth)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        verify=False,
        limits=httpx.Limits(
            max_connections=MAX_CONCURRENT + 5,
            max_keepalive_connections=10,
        ),
    ) as client:
        idor_findings, auth_findings = await asyncio.gather(
            idor_scanner.scan(client, urls),
            auth_scanner.scan(client, urls),
        )

    all_findings = idor_findings + auth_findings
    chains: list[dict[str, Any]] = [
        {
            "finding_id": f.id,
            "source_module": f.chain_source,
            "attack_surface": f.finding_type,  # already str via use_enum_values
            "severity": f.severity,             # already str via use_enum_values
            "priority": "high" if f.severity in (_CRITICAL_STR, _HIGH_STR) else "medium",
        }
        for f in all_findings
        if f.chain_source is not None
    ]

    log.info(
        f"[AuthScan] {target} — findings={len(all_findings)} "
        f"critical={sum(1 for f in all_findings if f.severity == _CRITICAL_STR)}"
    )

    return AuthScanResult(
        target=target,
        findings=all_findings,
        tested_endpoints=len(urls),
        confirmed_vulns=len(all_findings),
        chain_opportunities=chains,
    )


# Public sync entry point
def scan_broken_auth_idor(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    stealth: bool = False,
) -> AuthScanResult:
    """
    Scan live hosts for broken authentication and IDOR vulnerabilities.

    Sync wrapper around asyncio.run — compatible with PHANTOM's synchronous
    _run_step pipeline dispatcher.

    Args:
        probe_result:  Live host detection output (Step 7).
        param_result:  Parameter discovery output (Step 13).
        js_result:     Optional JS analysis output (Step 12) for endpoint enrichment.
        timeout:       Per-request timeout in seconds.
        stealth:       Add random inter-request delays to avoid WAF triggering.

    Returns:
        AuthScanResult with all findings, stats, and chain opportunities.

    Raises:
        RuntimeError: If no live hosts are available.
        ValueError:   If timeout is non-positive.
        TypeError:    If injectable_urls contains non-string elements.
    """
    if not probe_result.live_hosts:
        raise RuntimeError("No live hosts available for auth/IDOR scan.")
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")
    if not param_result.injectable_urls:
        log.warning("[AuthScan] No injectable URLs — IDOR detection will be limited to static paths.")

    return asyncio.run(
        _run_scan(
            target=probe_result.target,
            probe_result=probe_result,
            param_result=param_result,
            js_result=js_result,
            timeout=timeout,
            stealth=stealth,
        )
    )