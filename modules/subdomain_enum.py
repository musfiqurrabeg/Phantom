from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from config.settings import OUTPUT_DIR, HTTP_TIMEOUT
from core.logger import get_logger, section
from core.sanitize import safe_filename
from core.tool_checker import require_tools

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "subdomains"


# DATA MODEL
@dataclass
class SubdomainResult:
    """Holds the complete result of subdomain enumeration for one target."""
    target: str
    subdomains: set[str] = field(default_factory=set)
    sources: dict[str, list[str]] = field(default_factory=dict)

    @property
    def count(self):
        return len(self.subdomains)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total": self.count,
            "sources": {k: sorted(v) for k, v in self.sources.items()},
            "subdomains": sorted(self.subdomains)
        }
    
# SUBFINDER
def _run_subfinder(target: str) -> list[str]:
    """
    Runs subfinder against target.
    Returns list of discovered subdomains.
    Subfinder is fast and uses passive sources (certs, DNS, APIs).
    """
    log.info(f"[Subfinder] Starting on {target}")
    cmd = [
        "subfinder",
        "-d", 
        target,
        "-silent",
        "-timeout", str(HTTP_TIMEOUT),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log.warning("[Subfinder] Timed out after 120s — partial results used")
        return []
    except FileNotFoundError:
        log.error("[Subfinder] Binary not found — skipping")
        return []

    subdomains = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and "." in line
    ]

    log.info(f"[Subfinder] Found {len(subdomains)} subdomains")
    return subdomains

def _run_amass(target: str) -> list[str]:
    """
    Runs amass in passive mode against target.
    Passive mode = no active probing, stealth-safe.
    Amass goes deeper than subfinder using different data sources.
    """
    log.info(f"[Amass] Starting on {target}")

    cmd = [
        "amass", "enum",
        "-passive",
        "-d", target,
        "-timeout", "2",  # amass timeout is in minutes
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=150,
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log.warning("[Amass] Timed out after 150s — partial results used")
        return []
    except FileNotFoundError:
        log.error("[Amass] Binary not found — skipping")
        return []

    subdomains = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and target in line and "." in line
    ]

    log.info(f"[Amass] Found {len(subdomains)} subdomains")
    return subdomains

# SAVE RESULTS
def _save_results(result: SubdomainResult) -> Path:
    """
    Saves results to output/subdomains/<target>.json
    Creates directory if it doesn't exist.
    Returns path to saved file.
    """

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    
    safe_name = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_subdomains.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[Subdomains] Results saved → {output_file}")
    return output_file

# MAIN ENTRY POINT
def enumerate_subdomains(target: str) -> SubdomainResult:
    """
    Runs Subfinder + Amass against target. Merges and deduplicates all findings.
    Saves results to JSON. Returns SubdomainResult.
    """
    require_tools(["subfinder", "amass"])
    section(f"Subdomain Enumeration → {target}")

    result = SubdomainResult(target=target)

    # RUN BOTH TOOLS
    subfinder_hits = _run_subfinder(target=target)
    amass_hits = _run_amass(target=target)
    result.sources["subfinder"] = subfinder_hits
    result.sources["amass"]     = amass_hits

    # Merge + deduplicate using a set
    result.subdomains = set(subfinder_hits) | set(amass_hits)

    # Summary
    log.info(f"[Subdomains] Total unique: {result.count}")
    for subdomain in sorted(result.subdomains):
        log.info(f"  ↳ {subdomain}")

    _save_results(result)
    return result