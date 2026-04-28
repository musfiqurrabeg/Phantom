# modules/tech_fingerprint.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from config.settings import HTTP_TIMEOUT, HTTP_VERIFY_SSL, OUTPUT_DIR
from core.logger import get_logger, section
from modules.host_probe import ProbeResult, HostRecord

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "fingerprints"

# Header-based signatures: { header_name: { pattern: technology } }
HEADER_SIGNATURES: dict[str, dict[str, str]] = {
    "server": {
        r"apache": "Apache",
        r"nginx": "Nginx",
        r"microsoft-iis": "IIS",
        r"cloudflare": "Cloudflare",
        r"litespeed": "LiteSpeed",
        r"openresty": "OpenResty/Nginx",
        r"gunicorn": "Gunicorn/Python",
        r"uvicorn": "Uvicorn/Python",
        r"caddy": "Caddy",
    },
    "x-powered-by": {
        r"php": "PHP",
        r"asp\.net": "ASP.NET",
        r"express": "Express/Node.js",
        r"next\.js": "Next.js",
        r"django": "Django",
    },
    "x-generator": {
        r"wordpress": "WordPress",
        r"drupal": "Drupal",
        r"joomla": "Joomla",
    },
    "x-drupal-cache": {
        r".*": "Drupal",
    },
    "x-wp-total": {
        r".*": "WordPress",
    },
    "cf-ray": {
        r".*": "Cloudflare WAF",
    },
    "x-sucuri-id": {
        r".*": "Sucuri WAF",
    },
    "x-firewall-protection": {
        r".*": "Generic WAF",
    },
}

# Cookie name signatures
COOKIE_SIGNATURES: dict[str, str] = {
    "wordpress_logged_in": "WordPress",
    "wp-settings": "WordPress",
    "joomla_user_state": "Joomla",
    "drupal": "Drupal",
    "laravel_session": "Laravel/PHP",
    "csrftoken": "Django/Python",
    "rack.session": "Ruby on Rails",
    "phpsessid": "PHP",
    "aspsessionid": "ASP.NET",
    "connect.sid": "Express/Node.js",
}

# HTML body signatures: { pattern: technology }
BODY_SIGNATURES: dict[str, str] = {
    r"/wp-content/": "WordPress",
    r"/wp-includes/": "WordPress",
    r"wp-json": "WordPress REST API",
    r"joomla": "Joomla",
    r"/sites/default/files/": "Drupal",
    r"drupal\.settings": "Drupal",
    r"laravel": "Laravel",
    r"__django": "Django",
    r"csrf-token.*rails": "Ruby on Rails",
    r"ng-version": "Angular",
    r"__next": "Next.js",
    r"react\.development": "React",
    r"vue\.runtime": "Vue.js",
    r"shopify\.com": "Shopify",
    r"cdn\.magento\.com": "Magento",
    r"wix\.com": "Wix",
    r"squarespace\.com": "Squarespace",
}

# Known paths that confirm a technology
PROBE_PATHS: dict[str, str] = {
    "/wp-login.php": "WordPress",
    "/wp-admin/": "WordPress",
    "/administrator/": "Joomla",
    "/user/login": "Drupal",
    "/xmlrpc.php": "WordPress XML-RPC",
    "/.env": "Exposed .env File",
    "/config.php": "Exposed Config",
    "/server-status": "Apache Server Status",
    "/phpinfo.php": "PHP Info Exposed",
    "/.git/HEAD": "Exposed Git Repo",
}

# Security headers that should exist
SECURITY_HEADERS: list[str] = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Data Models
@dataclass
class FingerprintResult:
    """Complete technology fingerprint for a single host."""
    hostname: str
    url: str
    technologies: list[str] = field(default_factory=list)
    waf_detected: str | None = None
    missing_headers: list[str] = field(default_factory=list)
    exposed_paths: list[str] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "url": self.url,
            "technologies": sorted(set(self.technologies)),
            "waf_detected": self.waf_detected,
            "missing_headers": self.missing_headers,
            "exposed_paths": self.exposed_paths,
            "raw_headers": self.raw_headers,
        }
    
@dataclass
class TechScanResult:
    """Aggregated fingerprint results for all hosts under a target."""
    target:  str
    results: list[FingerprintResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hosts_scanned": len(self.results),
            "fingerprints": [r.to_dict() for r in self.results],
        }
    
# Fingerprint Logic
def _match_headers(headers: dict[str, str]) -> tuple[list[str], str | None]:
    """
    Matches response headers against HEADER_SIGNATURES.
    Returns (technologies, waf_name | None).
    """
    technologies: list[str] = []
    waf: str | None = None

    for header_name, patterns in HEADER_SIGNATURES.items():
        header_value = headers.get(header_name, "").lower()
        if not header_value:
            continue

        for pattern, tech in patterns.items():
            if re.search(pattern, header_value, re.IGNORECASE):
                if "WAF" in tech:
                    waf = tech
                else:
                    technologies.append(tech)
    return technologies, waf

def _match_cookies(headers: dict[str, str]) -> list[str]:
    """Extracts Set-Cookie header and matches against COOKIE_SIGNATURES."""
    technologies: list[str] = []
    cookie_header = headers.get("set-cookie", "").lower()

    if not cookie_header:
        return technologies

    for cookie_name, tech in COOKIE_SIGNATURES.items():
        if cookie_name.lower() in cookie_header:
            technologies.append(tech)

    return technologies


def _match_body(body: str) -> list[str]:
    """Scans HTML body for technology signatures."""
    technologies: list[str] = []

    for pattern, tech in BODY_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            technologies.append(tech)

    return technologies

def _check_security_headers(headers: dict[str, str]) -> list[str]:
    """Returns list of missing security headers."""
    return [
        header
        for header in SECURITY_HEADERS
        if header not in headers
    ]

# HTTP Fetcher
def _fetch(client: httpx.Client, url: str) -> httpx.Response | None:
    """
    Fetches a URL synchronously.
    Returns Response or None on any network/timeout error.
    """
    try:
        return client.get(url, follow_redirects=True)
    except httpx.TimeoutException:
        log.warning(f"[Fingerprint] Timeout → {url}")
        return None
    except httpx.RequestError as exc:
        log.warning(f"[Fingerprint] Request error → {url}: {exc}")
        return None
    
# Path Prober
def _probe_known_paths(client: httpx.Client, base_url: str) -> list[str]:
    """
    Probes known sensitive paths against the target.
    Returns list of paths that returned HTTP 200.
    """
    exposed: list[str] = []

    for path, label in PROBE_PATHS.items():
        url      = f"{base_url.rstrip('/')}{path}"
        response = _fetch(client, url)

        if response is not None and response.status_code == 200:
            log.warning(f"[Fingerprint] EXPOSED → {url} ({label})")
            exposed.append(f"{path} [{label}]")

    return exposed

# Single Host Fingerprinter
def _fingerprint_host(client: httpx.Client, host: HostRecord) -> FingerprintResult:
    """
    Fingerprints a single live host.
    Fetches root URL, analyzes headers + body + cookies.
    Probes known sensitive paths.
    """
    log.info(f"[Fingerprint] Analyzing → {host.url}")

    result = FingerprintResult(
        hostname=host.hostname,
        url=host.url,
    )

    response = _fetch(client, host.url)
    if response is None:
        log.warning(f"[Fingerprint] No response from {host.url} — skipping")
        return result

    # Normalize headers to lowercase keys
    headers = {k.lower(): v for k, v in response.headers.items()}
    body    = response.text

    result.raw_headers = dict(headers)

    # Run all matchers
    header_techs, waf = _match_headers(headers)
    cookie_techs = _match_cookies(headers)
    body_techs = _match_body(body)
    missing_headers = _check_security_headers(headers)
    exposed_paths = _probe_known_paths(client, host.url)

    result.technologies = header_techs + cookie_techs + body_techs
    result.waf_detected = waf
    result.missing_headers = missing_headers
    result.exposed_paths = exposed_paths

    # Log summary
    unique_techs = sorted(set(result.technologies))
    log.info(f"[Fingerprint] {host.hostname} → {', '.join(unique_techs) or 'Unknown stack'}")

    if waf:
        log.warning(f"[Fingerprint] WAF detected: {waf}")

    if missing_headers:
        log.warning(f"[Fingerprint] Missing security headers: {', '.join(missing_headers)}")

    if exposed_paths:
        log.warning(f"[Fingerprint] Exposed paths found: {len(exposed_paths)}")

    return result



# Save Results
def _save_results(result: TechScanResult) -> Path:
    """Saves TechScanResult to output/fingerprints/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name   = result.target.replace(".", "_")
    output_file = OUTPUT_PATH / f"{safe_name}_fingerprint.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[Fingerprint] Results saved → {output_file}")
    return output_file


# Main Entry Point
def fingerprint_technologies(probe_result: ProbeResult) -> TechScanResult:
    """
    Takes ProbeResult from Step 7 (live hosts).
    Fingerprints every live host's tech stack.
    Returns TechScanResult.
    """
    section(f"Technology Fingerprinting → {probe_result.target}")
    scan_result = TechScanResult(target=probe_result.target)

    if not probe_result.live_hosts:
        log.warning("[Fingerprint] No live hosts to fingerprint — skipping")
        return scan_result

    timeout = httpx.Timeout(connect=5.0, read=HTTP_TIMEOUT, write=5.0, pool=5.0)
    with httpx.Client(
        timeout=timeout,
        verify=HTTP_VERIFY_SSL,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"},
    ) as client:
        for host in probe_result.live_hosts:
            fingerprint = _fingerprint_host(client, host)
            scan_result.results.append(fingerprint)

    log.info(f"[Fingerprint] Complete — {len(scan_result.results)} host(s) analyzed")
    _save_results(scan_result)
    return scan_result