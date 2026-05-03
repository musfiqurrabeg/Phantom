# modules/wayback_harvest.py
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from config.settings import OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename
from core.tool_checker import require_tools

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "wayback"

# ── CLASSIFICATION PATTERNS ──────────────────────────────────

# File extensions worth targeting
JUICY_EXTENSIONS: frozenset[str] = frozenset({
    ".php", ".asp", ".aspx", ".jsp", ".json", ".xml",
    ".yaml", ".yml", ".env", ".config", ".conf", ".ini",
    ".log", ".bak", ".backup", ".sql", ".db", ".tar",
    ".zip", ".gz", ".pem", ".key", ".txt",
})

# URL path patterns that signal high-value targets
HIGH_VALUE_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"/admin",
        r"/api/",
        r"/v\d+/",           # versioned APIs: /v1/, /v2/
        r"/internal",
        r"/debug",
        r"/test",
        r"/dev",
        r"/staging",
        r"/backup",
        r"/upload",
        r"/export",
        r"/download",
        r"/config",
        r"/secret",
        r"/private",
        r"/dashboard",
        r"/manage",
        r"/swagger",
        r"/graphql",
        r"/\.git",
        r"/\.env",
    )
)

# Parameter names that are injection-prone
INJECTABLE_PARAMS: frozenset[str] = frozenset({
    "id", "user", "username", 
    "email", "name", "search",
    "query", "q", "file", 
    "path", "url", "redirect",
    "next", "page", "limit", 
    "offset", "sort", "order",
    "token", "key", "api_key", 
    "callback", "return", "ref", 
    "lang", "cat", "category", 
    "type", "action","cmd", 
    "exec", "command", "load", 
    "read", "write","include", 
    "require", "src", "dest", "target",
})

# Data Models
@dataclass
class ClassifiedURL:
    """A single URL with its classification metadata."""
    url: str
    path: str
    extension: str | None
    parameters: dict[str, list[str]]
    is_high_value: bool
    has_injectable: bool
    matched_patterns: list[str]

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "extension": self.extension,
            "parameters": self.parameters,
            "is_high_value": self.is_high_value,
            "has_injectable": self.has_injectable,
            "matched_patterns": self.matched_patterns,
        }
    
@dataclass
class WaybackResult:
    """Complete wayback harvest result for a single target."""
    target: str
    total_urls: int = 0
    high_value: list[ClassifiedURL] = field(default_factory=list)
    with_params: list[ClassifiedURL] = field(default_factory=list)
    juicy_files: list[ClassifiedURL] = field(default_factory=list)
    all_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_urls": self.total_urls,
            "stats": {
                "high_value": len(self.high_value),
                "with_params": len(self.with_params),
                "juicy_files": len(self.juicy_files),
            },
            "high_value": [u.to_dict() for u in self.high_value],
            "with_params": [u.to_dict() for u in self.with_params],
            "juicy_files": [u.to_dict() for u in self.juicy_files],
        }

def _run_waybackurls(target: str) -> list[str]:
    """
    Runs waybackurls binary against target domain.
    Returns raw list of historical URLs.
    waybackurls reads domain from stdin and outputs one URL per line.
    """
    log.info(f"[Wayback] Fetching historical URLs for {target}")

    try:
        result = subprocess.run(
            ["waybackurls", target],
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log.warning("[Wayback] Timed out after 120s — partial results used")
        return []
    except FileNotFoundError:
        log.error("[Wayback] waybackurls binary not found")
        return []

    if result.returncode != 0 and result.stderr.strip():
        log.warning(f"[Wayback] stderr: {result.stderr.strip()[:200]}")

    urls = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("http")
    ]

    log.info(f"[Wayback] Raw URLs fetched: {len(urls)}")
    return urls


# URL CLASSIFIER
def _classify_url(raw_url: str) -> ClassifiedURL | None:
    """
    Parses and classifies a single URL.
    Returns None if URL is malformed or unparseable.
    """
    try:
        parsed = urlparse(raw_url)
    except ValueError:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None

    path      = parsed.path or "/"
    extension = Path(path).suffix.lower() or None
    params    = parse_qs(parsed.query, keep_blank_values=False)

    # Check high-value path patterns
    matched_patterns: list[str] = [
        pattern.pattern
        for pattern in HIGH_VALUE_PATTERNS
        if pattern.search(path)
    ]
    is_high_value = bool(matched_patterns)

    # Check for injectable parameter names
    param_names     = {k.lower() for k in params}
    has_injectable  = bool(param_names & INJECTABLE_PARAMS)

    return ClassifiedURL(
        url=raw_url,
        path=path,
        extension=extension,
        parameters=params,
        is_high_value=is_high_value,
        has_injectable=has_injectable,
        matched_patterns=matched_patterns,
    )


# DEDUPLICATOR
def _deduplicate(urls: list[str]) -> list[str]:
    """
    Removes duplicate URLs using a seen-set.
    Also strips query string duplicates with identical param keys
    to reduce noise (keeps first occurrence).
    """
    seen_full: set[str]    = set()
    seen_normalized: set[str] = set()
    unique: list[str]      = []

    for url in urls:
        if url in seen_full:
            continue

        try:
            parsed = urlparse(url)
        except ValueError:
            continue

        # Normalize: scheme + netloc + path + sorted param keys
        param_keys = tuple(sorted(parse_qs(parsed.query).keys()))
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(param_keys)}"

        if normalized in seen_normalized:
            continue

        seen_full.add(url)
        seen_normalized.add(normalized)
        unique.append(url)

    return unique


# SAVE RESULTS
def _save_results(result: WaybackResult) -> Path:
    """Saves WaybackResult to output/wayback/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name   = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_wayback.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    # Also save raw URL list for use by other modules
    raw_file = OUTPUT_PATH / f"{safe_name}_urls_raw.txt"
    with raw_file.open("w", encoding="utf-8") as f:
        f.write("\n".join(result.all_urls))

    log.info(f"[Wayback] Results saved → {output_file}")
    log.info(f"[Wayback] Raw URLs saved → {raw_file}")
    return output_file


# MAIN ENTRY POINT
def harvest_wayback_urls(target: str) -> WaybackResult:
    """
    Fetches all historical URLs for target from Wayback Machine.
    Deduplicates, classifies, and saves results.
    Returns WaybackResult with categorized URL lists.
    """
    require_tools(["waybackurls"])
    section(f"Wayback URL Harvesting → {target}")

    result = WaybackResult(target=target)

    # Fetch
    raw_urls   = _run_waybackurls(target)
    deduped    = _deduplicate(raw_urls)
    result.total_urls = len(deduped)
    result.all_urls   = deduped

    log.info(f"[Wayback] Unique URLs after dedup: {len(deduped)}")

    if not deduped:
        log.warning("[Wayback] No URLs found — target may not be indexed")
        _save_results(result)
        return result

    # Classify
    for raw_url in deduped:
        classified = _classify_url(raw_url)
        if classified is None:
            continue

        if classified.is_high_value:
            result.high_value.append(classified)
            log.info(f"  [HIGH] {classified.url}")

        if classified.parameters:
            result.with_params.append(classified)

        if classified.extension in JUICY_EXTENSIONS:
            result.juicy_files.append(classified)
            log.info(f"  [FILE] {classified.url}")

    # Summary
    log.info(f"  [Wayback] High-value URLs:  {len(result.high_value)}")
    log.info(f"  [Wayback] URLs with params: {len(result.with_params)}")
    log.info(f"  [Wayback] Juicy files:      {len(result.juicy_files)}")

    # Warn on injectable params found
    injectable_urls = [u for u in result.with_params if u.has_injectable]
    if injectable_urls:
        log.warning(f"  [Wayback] Injectable param URLs: {len(injectable_urls)} — prime SQLi/XSS targets")

    _save_results(result)
    return result