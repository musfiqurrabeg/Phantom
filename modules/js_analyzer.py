# modules/js_analyzer.py
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from config.settings import HTTP_TIMEOUT, HTTP_VERIFY_SSL, MAX_THREAD, OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename
from modules.host_probe import ProbeResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "js_analysis"

# CONCURRENCY
JS_FETCH_CONCURRENCY: int = MAX_THREAD
JS_MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024   # 5MB cap — minified JS can be huge
JS_FETCH_TIMEOUT: float = float(HTTP_TIMEOUT)

# SECRET PATTERNS
# Each entry: (category, severity, compiled_pattern)
# Ordered by severity descending so highest hits log first

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass(frozen=True)
class SecretPattern:
    category: str
    severity: Severity
    pattern:  re.Pattern


SECRET_PATTERNS: tuple[SecretPattern, ...] = tuple(
    SecretPattern(category=cat, severity=sev, pattern=re.compile(pat, re.IGNORECASE))
    for cat, sev, pat in (
        # CRITICAL
        ("AWS Access Key", Severity.CRITICAL, r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Key", Severity.CRITICAL, r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
        ("Private Key (PEM)", Severity.CRITICAL, r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        ("GCP Service Account", Severity.CRITICAL, r'"type"\s*:\s*"service_account"'),
        ("Stripe Secret Key", Severity.CRITICAL, r"sk_live_[0-9a-zA-Z]{24,}"),
        ("Twilio Auth Token", Severity.CRITICAL, r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]"),
        
        # HIGH
        ("GitHub Token", Severity.HIGH, r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}"),
        ("Slack Bot Token", Severity.HIGH, r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}"),
        ("Slack Webhook", Severity.HIGH, r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}"),
        ("Firebase URL", Severity.HIGH, r"https://[a-z0-9-]+\.firebaseio\.com"),
        ("Firebase API Key", Severity.HIGH, r"AIza[0-9A-Za-z\-_]{35}"),
        ("Heroku API Key", Severity.HIGH, r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        ("SendGrid API Key", Severity.HIGH, r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
        ("Mailgun API Key", Severity.HIGH, r"key-[0-9a-zA-Z]{32}"),
        ("JWT Token", Severity.HIGH, r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        ("Basic Auth in URL", Severity.HIGH, r"https?://[^:@\s]+:[^:@\s]+@[^@\s]+"),
        ("Stripe Publishable Key", Severity.HIGH, r"pk_live_[0-9a-zA-Z]{24,}"),
        
        # MEDIUM
        ("Generic API Key", Severity.MEDIUM, r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]"),
        ("Generic Secret", Severity.MEDIUM, r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        ("Generic Token", Severity.MEDIUM, r"(?i)(?:token|access_token|auth_token)\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{16,}['\"]"),
        ("S3 Bucket URL", Severity.MEDIUM, r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com"),
        ("Internal IP Address", Severity.MEDIUM, r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"),
        ("MongoDB URI", Severity.MEDIUM, r"mongodb(?:\+srv)?://[^\s'\"]+"),
        ("PostgreSQL URI", Severity.MEDIUM, r"postgres(?:ql)?://[^\s'\"]+"),
        ("Redis URI", Severity.MEDIUM, r"redis://[^\s'\"]+"),
        
        # LOW
        ("Email Address", Severity.LOW, r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        ("Version String", Severity.LOW, r"(?i)version\s*[:=]\s*['\"][\d.]+['\"]"),
        
        # INFO
        ("Debug Flag", Severity.INFO, r"(?i)(?:debug|verbose)\s*[:=]\s*true"),
        ("TODO/FIXME Comment", Severity.INFO, r"(?i)//\s*(?:todo|fixme|hack|xxx|bug):?\s*.+"),
    )
)

# ENDPOINT PATTERNS
ENDPOINT_PATTERNS: tuple[re.Pattern, ...] = (
    # REST paths: /api/v1/users, /internal/admin
    re.compile(r"""['"`](\/([\w\-\.]+\/){1,6}[\w\-\.]*(?:\?[\w=&%+\-.]*)?)['"`]"""),
    
    # Full URLs embedded in JS
    re.compile(r"""['"`](https?://[^\s'"`<>]{10,})['"`]"""),
    
    # fetch() and axios() calls
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`]+)['"`]"""),
    
    # GraphQL endpoints
    re.compile(r"""['"`]([^'"`]*graphql[^'"`]*)['"`]""", re.IGNORECASE),
    
    # XMLHttpRequest
    re.compile(r"""\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]"""),
)

# Noise paths to exclude from endpoint results
ENDPOINT_NOISE: frozenset[str] = frozenset({
    "/", "//", "/favicon.ico", "/robots.txt",
    "application/json", "text/html", "text/plain",
})




# DATA MODELS
@dataclass
class SecretFinding:
    """A single secret or sensitive value found in a JS file."""
    js_url: str
    category: str
    severity: Severity
    match: str       # The actual matched string (truncated for safety)
    context: str       # Surrounding code for context

    def to_dict(self) -> dict:
        return {
            "js_url": self.js_url,
            "category": self.category,
            "severity": self.severity.value,
            "match": self.match[:120],   # Never store full secrets
            "context": self.context[:200],
        }



@dataclass
class EndpointFinding:
    """An API endpoint or internal URL discovered in JS."""
    js_url: str
    endpoint: str
    is_api: bool
    is_full_url: bool

    def to_dict(self) -> dict:
        return {
            "js_url": self.js_url,
            "endpoint": self.endpoint,
            "is_api": self.is_api,
            "is_full_url": self.is_full_url,
        }




@dataclass
class JSFileResult:
    """Analysis result for a single JavaScript file."""
    url: str
    size_bytes: int
    secrets:   list[SecretFinding] = field(default_factory=list)
    endpoints: list[EndpointFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "size_bytes": self.size_bytes,
            "secret_count": len(self.secrets),
            "endpoint_count": len(self.endpoints),
            "secrets": [s.to_dict() for s in self.secrets],
            "endpoints": [e.to_dict() for e in self.endpoints],
        }




@dataclass
class JSAnalysisResult:
    """Complete JS analysis result for a target."""
    target: str
    js_files: list[JSFileResult] = field(default_factory=list)
    all_endpoints: list[str] = field(default_factory=list)

    @property
    def total_secrets(self) -> int:
        return sum(len(f.secrets) for f in self.js_files)

    @property
    def critical_secrets(self) -> list[SecretFinding]:
        return [
            s
            for f in self.js_files
            for s in f.secrets
            if s.severity == Severity.CRITICAL
        ]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "js_files_found": len(self.js_files),
            "total_secrets": self.total_secrets,
            "all_endpoints": sorted(set(self.all_endpoints)),
            "files": [f.to_dict() for f in self.js_files],
        }



# JS URL EXTRACTOR
def _extract_js_urls(html: str, base_url: str) -> list[str]:
    """
    Parses HTML page and extracts all <script src="..."> URLs.
    Resolves relative URLs against base_url.
    Filters out external CDN scripts — we only want app JS.
    """
    base_host = urlparse(base_url).netloc
    soup = BeautifulSoup(html, "html.parser")
    js_urls: list[str] = []

    for tag in soup.find_all("script", src=True):
        src_value = tag.get("src")
        if not src_value:
            continue

        src = str(src_value).strip()
        if not src:
            continue

        full_url = urljoin(base_url, src)
        parsed   = urlparse(full_url)

        # Keep only same-host scripts — external CDNs aren't useful
        if parsed.netloc and parsed.netloc != base_host:
            continue

        if full_url not in js_urls:
            js_urls.append(full_url)

    return js_urls


# SECRET SCANNER
def _scan_secrets(js_url: str, content: str) -> list[SecretFinding]:
    """
    Runs all SECRET_PATTERNS against JS content.
    Returns deduplicated SecretFinding list sorted by severity.
    """
    findings: list[SecretFinding] = []
    seen_matches: set[str]        = set()

    for sp in SECRET_PATTERNS:
        for match in sp.pattern.finditer(content):
            matched_str = match.group(0)

            # Deduplicate identical matches within same file
            dedup_key = f"{sp.category}:{matched_str[:60]}"
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)

            # Extract surrounding context (50 chars each side)
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ").strip()

            findings.append(SecretFinding(
                js_url=js_url,
                category=sp.category,
                severity=sp.severity,
                match=matched_str,
                context=context,
            ))

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    severity_order = {s: i for i, s in enumerate(Severity)}
    findings.sort(key=lambda f: severity_order[f.severity])
    return findings


# ENDPOINT EXTRACTOR
def _extract_endpoints(js_url: str, content: str, base_url: str) -> list[EndpointFinding]:
    """
    Extracts API endpoints and internal URLs from JS content.
    Deduplicates and filters noise paths.
    """
    base_host  = urlparse(base_url).netloc
    seen: set[str] = set()
    findings: list[EndpointFinding] = []

    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            endpoint = match.group(1).strip()

            if not endpoint or endpoint in ENDPOINT_NOISE:
                continue
            if len(endpoint) > 300:
                continue
            if endpoint in seen:
                continue

            seen.add(endpoint)
            parsed = urlparse(endpoint)
            is_protocol_relative = endpoint.startswith("//")
            is_full_url = bool(parsed.scheme) or is_protocol_relative
            is_api = bool(re.search(r"/api/|/v\d+/|/graphql|/rest/", endpoint, re.IGNORECASE))

            # Filter full URLs from external hosts — not useful
            if is_full_url and parsed.netloc and parsed.netloc != base_host:
                continue

            findings.append(EndpointFinding(
                js_url=js_url,
                endpoint=endpoint,
                is_api=is_api,
                is_full_url=is_full_url,
            ))

    return findings


# ASYNC JS FETCHER
async def _fetch_and_analyze_js(
    client: httpx.AsyncClient,
    js_url: str,
    base_url: str,
    sem: asyncio.Semaphore,
) -> JSFileResult | None:
    """
    Fetches a single JS file and runs secret + endpoint analysis.
    Returns None if fetch fails or file is too large.
    """
    async with sem:
        try:
            response = await client.get(js_url, follow_redirects=True)
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            log.warning(f"[JS] Fetch failed {js_url}: {type(exc).__name__}")
            return None

    if response.status_code != 200:
        return None

    content_length = len(response.content)
    if content_length > JS_MAX_FILE_SIZE_BYTES:
        log.warning(f"[JS] Skipping oversized file ({content_length // 1024}KB): {js_url}")
        return None

    content = response.text
    secrets = _scan_secrets(js_url, content)
    endpoints = _extract_endpoints(js_url, content, base_url)

    result = JSFileResult(
        url=js_url,
        size_bytes=content_length,
        secrets=secrets,
        endpoints=endpoints,
    )

    log.info(
        f"[JS] {js_url.split('/')[-1]:<40} "
        f"secrets={len(secrets):<4} endpoints={len(endpoints)}"
    )

    for secret in secrets:
        if secret.severity in (Severity.CRITICAL, Severity.HIGH):
            log.warning(f"  ⚠  [{secret.severity.value}] {secret.category}: {secret.match[:80]}")

    return result


# PAGE HTML FETCHER
async def _fetch_page_html(
    client: httpx.AsyncClient,
    page_url: str,
) -> str | None:
    """Fetches the HTML of a page to extract script tags."""
    try:
        response = await client.get(page_url, follow_redirects=True)
        if response.status_code == 200:
            return response.text
    except (httpx.TimeoutException, httpx.RequestError) as exc:
        log.warning(f"[JS] Page fetch failed {page_url}: {type(exc).__name__}")
    return None


# SAVE RESULTS
def _save_results(result: JSAnalysisResult) -> Path:
    """Saves JSAnalysisResult to output/js_analysis/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_js_analysis.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    # Save extracted endpoints as plain text for Steps 14+15
    endpoints_file = OUTPUT_PATH / f"{safe_name}_js_endpoints.txt"
    with endpoints_file.open("w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(result.all_endpoints))))

    log.info(f"[JS] Results saved → {output_file}")
    log.info(f"[JS] Endpoints saved → {endpoints_file}")
    return output_file


# ASYNC ORCHESTRATOR
async def _analyze_all_hosts(
    probe_result: ProbeResult,
) -> JSAnalysisResult:
    """
    Async core — fetches pages, discovers JS URLs, analyzes all files concurrently.
    """
    analysis = JSAnalysisResult(target=probe_result.target)
    sem = asyncio.Semaphore(JS_FETCH_CONCURRENCY)

    timeout = httpx.Timeout(connect=5.0, read=JS_FETCH_TIMEOUT, write=5.0, pool=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=HTTP_VERIFY_SSL,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"},
    ) as client:

        for host in probe_result.live_hosts:
            base_url = host.url
            log.info(f"[JS] Crawling page for JS files → {base_url}")

            html = await _fetch_page_html(client, base_url)
            if html is None:
                log.warning(f"[JS] Could not fetch page HTML for {base_url}")
                continue

            js_urls = _extract_js_urls(html, base_url)
            log.info(f"[JS] Found {len(js_urls)} script(s) on {host.hostname}")

            if not js_urls:
                continue

            tasks = [
                _fetch_and_analyze_js(client, js_url, base_url, sem)
                for js_url in js_urls
            ]

            file_results = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            for file_result in file_results:
                if isinstance(file_result, BaseException):
                    log.warning(
                        f"[JS] Worker failed on host {host.hostname}: "
                        f"{type(file_result).__name__}: {file_result}"
                    )
                    continue
                if file_result is None:
                    continue

                analysis.js_files.append(file_result)
                analysis.all_endpoints.extend(
                    e.endpoint for e in file_result.endpoints
                )

    return analysis


# MAIN ENTRY POINT
def analyze_javascript(probe_result: ProbeResult) -> JSAnalysisResult:
    """
    Crawls all live hosts, discovers JS files, extracts secrets + endpoints.
    Takes ProbeResult from Step 7.
    Returns JSAnalysisResult.
    """
    section(f"JavaScript Analysis → {probe_result.target}")
    if not probe_result.live_hosts:
        log.warning("[JS] No live hosts to analyze — skipping")
        return JSAnalysisResult(target=probe_result.target)

    result = asyncio.run(_analyze_all_hosts(probe_result))

    
    # Final Summary 
    log.info(f"[JS] Files analyzed: {len(result.js_files)}")
    log.info(f"[JS] Total secrets: {result.total_secrets}")
    log.info(f"[JS] Unique endpoints: {len(set(result.all_endpoints))}")

    if result.critical_secrets:
        log.warning(f"[JS] ⚠ CRITICAL secrets found: {len(result.critical_secrets)}")
        for s in result.critical_secrets:
            log.warning(f" → [{s.js_url}] {s.category}")

    _save_results(result)
    return result