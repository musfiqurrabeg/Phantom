# modules/param_discovery.py
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlencode, urljoin

import httpx

from config.settings import HTTP_TIMEOUT, HTTP_VERIFY_SSL, OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename
from core.tool_checker import require_tools
from modules.host_probe import ProbeResult
from modules.wayback_harvest import WaybackResult
from modules.js_analyzer import JSAnalysisResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "parameters"

# CONSTANTS

# Arjun thread count — higher = faster but noisier
ARJUN_THREADS: int = 20

# Arjun request timeout per URL
ARJUN_TIMEOUT: int = HTTP_TIMEOUT

# Max URLs to send to Arjun per host — cap to avoid multi-hour runs
MAX_URLS_PER_HOST: int = 50

# HTTP methods to test parameter discovery on
PROBE_METHODS: tuple[str, ...] = ("GET", "POST")

# Parameters that are high-priority injection targets
CRITICAL_PARAMS: frozenset[str] = frozenset({
    "id", "user_id", "uid", 
    "userid", "file", "path", 
    "dir", "filename","url", 
    "redirect", "next", "return", 
    "dest", "cmd", "exec", 
    "command", "shell","query", 
    "search", "q", "keyword",
    "token", "key", "api_key",
    "auth", "email", "username", 
    "user", "name","page",
    "limit", "offset", "sort",
    "debug", "admin", "test", 
    "mode", "callback", "jsonp", 
    "include", "load"
})

# Params to ignore — these are noise, not attack surface
PARAM_NOISE: frozenset[str] = frozenset({
    "utm_source", "utm_medium", 
    "utm_campaign", "utm_term", 
    "utm_content", "fbclid", 
    "gclid", "_ga", 
    "ref", "source"
})

# DATA MODELS
@dataclass
class DiscoveredParam:
    """A single discovered parameter on a URL."""
    url: str
    param_name: str
    method: str       # GET or POST
    is_critical: bool      # High-priority injection target

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "param_name": self.param_name,
            "method": self.method,
            "is_critical": self.is_critical,
        }


@dataclass
class URLParamResult:
    """Parameter discovery result for a single URL."""
    url:    str
    method: str
    params: list[DiscoveredParam] = field(default_factory=list)

    @property
    def critical_params(self) -> list[DiscoveredParam]:
        return [p for p in self.params if p.is_critical]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "param_count": len(self.params),
            "critical_count": len(self.critical_params),
            "params": [p.to_dict() for p in self.params],
        }


@dataclass
class ParamScanResult:
    """Complete parameter discovery result for a target."""
    target: str
    url_results: list[URLParamResult] = field(default_factory=list)

    @property
    def total_params(self) -> int:
        return sum(len(r.params) for r in self.url_results)

    @property
    def all_critical(self) -> list[DiscoveredParam]:
        return [
            p
            for r in self.url_results
            for p in r.params
            if p.is_critical
        ]

    @property
    def injectable_urls(self) -> list[str]:
        """URLs with at least one critical parameter — prime attack targets."""
        return [
            r.url
            for r in self.url_results
            if r.critical_params
        ]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "urls_scanned": len(self.url_results),
            "total_params": self.total_params,
            "critical_params": len(self.all_critical),
            "injectable_urls": self.injectable_urls,
            "results": [r.to_dict() for r in self.url_results],
        }


# URL COLLECTOR
def _collect_target_urls(
    probe_result: ProbeResult,
    wayback_result: WaybackResult | None,
    js_result: JSAnalysisResult | None,
) -> list[str]:
    """
    Aggregates URLs from three sources:
    1. Live host base URLs (Step 7)
    2. Wayback URLs with parameters (Step 10)
    3. JS-extracted endpoints (Step 12)

    Deduplicates by normalized URL. Returns at most MAX_URLS_PER_HOST
    per host to prevent unbounded scan time.
    """
    collected: list[str] = []
    seen: set[str] = set()
    host_counts: dict[str, int] = {}
    capped_hosts: set[str] = set()

    def _add(url: str) -> None:
        url = url.strip()
        if not url or url in seen:
            return
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return

        host = (parsed.hostname or "").lower()
        if not host:
            return

        current_count = host_counts.get(host, 0)
        if current_count >= MAX_URLS_PER_HOST:
            if host not in capped_hosts:
                log.warning(
                    f"[Arjun] URL cap reached for host {host} "
                    f"({MAX_URLS_PER_HOST}); additional URLs skipped"
                )
                capped_hosts.add(host)
            return

        seen.add(url)
        collected.append(url)
        host_counts[host] = current_count + 1

    # Source 1: live host base URLs
    for host in probe_result.live_hosts:
        _add(host.url)

    # Source 2: Wayback URLs that already have parameters
    if wayback_result:
        for classified in wayback_result.with_params:
            _add(classified.url)

    # Source 3: JS endpoints — resolve relative paths against each live host
    if js_result:
        for host in probe_result.live_hosts:
            for endpoint in js_result.all_endpoints:
                if endpoint.startswith("http"):
                    _add(endpoint)
                elif endpoint.startswith("/"):
                    _add(urljoin(host.url, endpoint))

    return collected


# ARJUN RUNNER
def _run_arjun(url: str, method: str) -> list[str]:
    """
    Runs Arjun against a single URL for one HTTP method.
    Uses JSON output for reliable parsing.
    Returns list of discovered parameter names.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, mode="w"
    ) as tmp:
        output_path = Path(tmp.name)

    cmd: list[str] = [
        "arjun",
        "-u", url,
        "-m", method,
        "-t", str(ARJUN_THREADS),
        "--timeout", str(ARJUN_TIMEOUT),
        "-oJ", str(output_path),
        "-q"  # Quiet — suppress banner
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            encoding="utf-8",
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(f"[Arjun] Timed out on {url} [{method}]")
        output_path.unlink(missing_ok=True)
        return []
    except FileNotFoundError:
        log.error("[Arjun] Binary not found")
        output_path.unlink(missing_ok=True)
        return []
    except OSError as exc:
        log.warning(f"[Arjun] Execution failed on {url} [{method}]: {exc}")
        output_path.unlink(missing_ok=True)
        return []

    if result.returncode not in (0, 1):
        log.warning(f"[Arjun] Exit code {result.returncode} on {url} [{method}]")
        if result.stderr.strip():
            log.warning(f"[Arjun] stderr: {result.stderr.strip()[:300]}")
        output_path.unlink(missing_ok=True)
        return []

    try:
        return _parse_arjun_output(output_path, url)
    finally:
        output_path.unlink(missing_ok=True)


def _parse_arjun_output(output_path: Path, url: str) -> list[str]:
    """
    Parses Arjun JSON output file.
    Arjun writes: { "url": [...params...] } or { "url": { "params": [...] } }
    Returns list of parameter name strings.
    """
    if not output_path.exists() or output_path.stat().st_size == 0:
        return []

    try:
        with output_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning(f"[Arjun] Output parse failed for {url}: {exc}")
        return []

    # Arjun output format varies by version — handle both shapes
    # Shape 1: { "url": ["param1", "param2"] }
    # Shape 2: { "url": { "params": ["param1", "param2"] } }
    for key, value in data.items():
        if isinstance(value, list):
            return [str(p) for p in value if p not in PARAM_NOISE]
        if isinstance(value, dict):
            raw_params = value.get("params", [])
            return [str(p) for p in raw_params if p not in PARAM_NOISE]

    return []


# FALLBACK HTML FORM PARSER
def _extract_form_params(url: str) -> list[str]:
    """
    Fallback: fetches the page and extracts <input>, <select>, <textarea>
    name attributes from HTML forms.
    Used when Arjun returns nothing — forms are always worth checking.
    """
    try:
        with httpx.Client(
            timeout=httpx.Timeout(connect=5.0, read=float(HTTP_TIMEOUT), write=5.0, pool=5.0),
            verify=HTTP_VERIFY_SSL,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"},
        ) as client:
            response = client.get(url)

        if response.status_code != 200:
            return []

    except (httpx.TimeoutException, httpx.RequestError):
        return []

    # Lightweight regex extraction — avoids BS4 import in this module
    import re
    pattern = re.compile(
        r"""<(?:input|select|textarea)[^>]+name\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    params = list(dict.fromkeys(
        m.group(1)
        for m in pattern.finditer(response.text)
        if m.group(1) not in PARAM_NOISE
    ))
    return params


# SINGLE URL PROCESSOR
def _process_url(url: str) -> list[URLParamResult]:
    """
    Runs Arjun on GET + POST for one URL.
    Falls back to form parsing if Arjun finds nothing on GET.
    Returns list of URLParamResult (one per method with findings).
    """
    results: list[URLParamResult] = []

    for method in PROBE_METHODS:
        log.info(f"[Arjun] {method} → {url}")
        raw_params = _run_arjun(url, method)

        # Fallback to form extraction on GET when Arjun finds nothing
        if not raw_params and method == "GET":
            raw_params = _extract_form_params(url)
            if raw_params:
                log.info(f"[Arjun] Form params found via HTML fallback: {raw_params}")

        if not raw_params:
            continue

        discovered = [
            DiscoveredParam(
                url=url,
                param_name=p,
                method=method,
                is_critical=p.lower() in CRITICAL_PARAMS,
            )
            for p in raw_params
        ]

        url_result = URLParamResult(url=url, method=method, params=discovered)
        results.append(url_result)

        for param in discovered:
            marker = " ★ CRITICAL" if param.is_critical else ""
            log.info(f"  ↳ [{method}] ?{param.param_name}{marker}")

    return results


# SAVE RESULTS
def _save_results(result: ParamScanResult) -> Path:
    """Saves ParamScanResult to output/parameters/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name   = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_params.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    # Save injectable URLs as plain text for Steps 14+15
    injectable_file = OUTPUT_PATH / f"{safe_name}_injectable_urls.txt"
    with injectable_file.open("w", encoding="utf-8") as f:
        f.write("\n".join(result.injectable_urls))

    log.info(f"[Arjun] Results saved       → {output_file}")
    log.info(f"[Arjun] Injectable URLs      → {injectable_file}")
    return output_file


# MAIN ENTRY POINT
def discover_parameters(
    probe_result:   ProbeResult,
    wayback_result: WaybackResult | None = None,
    js_result:      JSAnalysisResult | None = None,
) -> ParamScanResult:
    """
    Discovers hidden GET/POST parameters on all target URLs.
    Pulls URLs from live hosts (Step 7), Wayback (Step 10), JS endpoints (Step 12).
    Uses Arjun with HTML form fallback.
    Returns ParamScanResult with all discovered parameters.
    """
    section(f"Parameter Discovery → {probe_result.target}")

    scan_result = ParamScanResult(target=probe_result.target)

    target_urls = _collect_target_urls(probe_result, wayback_result, js_result)

    if not target_urls:
        log.warning("[Arjun] No URLs to probe — skipping")
        _save_results(scan_result)
        return scan_result

    try:
        require_tools(["arjun"])
    except RuntimeError as exc:
        log.warning(f"[Arjun] Skipping parameter discovery: {exc}")
        _save_results(scan_result)
        return scan_result

    log.info(f"[Arjun] Probing {len(target_urls)} URL(s) across GET + POST")

    for url in target_urls:
        url_results = _process_url(url)
        scan_result.url_results.extend(url_results)

    # Summary
    log.info(f"  [Arjun] Total parameters discovered: {scan_result.total_params}")
    log.info(f"  [Arjun] Critical parameters:         {len(scan_result.all_critical)}")
    log.info(f"  [Arjun] Injectable URLs:             {len(scan_result.injectable_urls)}")

    if scan_result.all_critical:
        log.warning("  [Arjun] Critical injection points:")
        for param in scan_result.all_critical:
            log.warning(f"  ★  [{param.method}] {param.url} → ?{param.param_name}")

    _save_results(scan_result)
    return scan_result