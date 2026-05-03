# modules/dir_bruteforce.py
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from config.settings import OUTPUT_DIR, DIR_WORDLIST, RATE_LIMIT_DELAY
from core.logger import get_logger, section
from core.sanitize import safe_filename
from core.tool_checker import require_tools
from modules.host_probe import ProbeResult, HostRecord

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "directories"

# CONSTANTS
# HTTP status codes worth reporting
INTERESTING_CODES: frozenset[int] = frozenset({
    200, 201, 204,       # Success
    301, 302, 307, 308,  # Redirects — follow manually
    401, 403,            # Auth required / Forbidden — worth noting
    405,                 # Method not allowed — endpoint exists
    500,                 # Server error — potential vuln
})

# Status codes to filter out (noise)
FILTER_CODES: str = "404,429"

# ffuf threading — high enough to be fast, low enough to avoid bans
FFUF_THREADS: int = 40

# ffuf request timeout in seconds
FFUF_TIMEOUT: int = 10

# Max lines to read from wordlist — cap at 5000 for speed
MAX_WORDLIST_LINES: int = 5000

# Paths that are especially high-value when found
HIGH_VALUE_PATHS: frozenset[str] = frozenset({
    "admin", "administrator", "wp-admin", "login", "signin",
    "api", "v1", "v2", "v3", "graphql", "swagger", "swagger-ui",
    "phpinfo.php", "info.php", "test.php", "debug",
    ".env", ".git", "config", "backup", "db", "database",
    "upload", "uploads", "files", "export", "dump",
    "console", "actuator", "metrics", "health", "status",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
})

# DATA MODELS
@dataclass
class DiscoveredPath:
    """A single discovered path from directory bruteforce."""
    url: str
    path: str
    status_code: int
    length: int
    words: int
    lines: int
    is_high_value: bool

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "status_code": self.status_code,
            "length": self.length,
            "words": self.words,
            "lines": self.lines,
            "is_high_value": self.is_high_value,
        }


@dataclass
class BruteForceResult:
    """Directory bruteforce results for a single host."""
    hostname: str
    base_url: str
    paths: list[DiscoveredPath] = field(default_factory=list)

    @property
    def high_value_paths(self) -> list[DiscoveredPath]:
        return [p for p in self.paths if p.is_high_value]
    
    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "base_url": self.base_url,
            "total_found": len(self.paths),
            "high_value_count": len(self.high_value_paths),
            "paths": [p.to_dict() for p in self.paths]
        }
    
@dataclass
class DirScanResult:
    """Aggregated bruteforce results for all hosts under a target."""
    target: str
    results: list[BruteForceResult] = field(default_factory=list)

    @property
    def total_paths(self) -> int:
        return sum(len(r.paths) for r in self.results)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_paths": self.total_paths,
            "hosts": [r.to_dict() for r in self.results]
        }
    

def _validate_wordlist(wordlist_path: str) -> Path:
    """
    Validates wordlist exists and is non-empty.
    Raises FileNotFoundError or ValueError on failure.
    """
    path = Path(wordlist_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {path}\n"
            f"Run: curl -L https://raw.githubusercontent.com/danielmiessler/"
            f"SecLists/master/Discovery/Web-Content/common.txt -o {path}"
        )

    if path.stat().st_size == 0:
        raise ValueError(f"Wordlist is empty: {path}")

    return path


# FFUF JSON PARSER
def _parse_ffuf_output(raw_json: str, base_url: str, hostname: str) -> list[DiscoveredPath]:
    """
    Parses ffuf's JSON output into DiscoveredPath list.
    ffuf -o stdout -of json produces a results array under key 'results'.
    Returns empty list on parse failure.
    """

    if not raw_json.strip():
        return []
    
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error(f"[ffuf] JSON parse failed for {hostname}: {exc}")
        return []
    

    raw_results = data.get("results", [])
    if not raw_results:
        return []
    

    discovered: list[DiscoveredPath] = []
    for entry in raw_results:
        try:
            status = int(entry.get("status", 0))
        except (TypeError, ValueError):
            continue
        
        if status not in INTERESTING_CODES:
            continue

        path = entry.get("input", {}).get("FUZZ", "").strip("/")
        url = entry.get("url", f"{base_url}/{path}")
        try:
            length = int(entry.get("length", 0))
            words = int(entry.get("words", 0))
            lines = int(entry.get("lines", 0))
        except (TypeError, ValueError):
            length, words, lines = 0, 0, 0
        is_high = path.lower() in HIGH_VALUE_PATHS

        discovered.append(DiscoveredPath(
            url=url,
            path=path,
            status_code=status,
            length=length,
            words=words,
            lines=lines,
            is_high_value=is_high,
        ))

    return discovered

# FFUF RUNNER
def _run_ffuf(host: HostRecord, wordlist_path: Path) -> list[DiscoveredPath]:
    """
    Runs ffuf against a single host.
    Uses JSON output mode for reliable parsing.
    Returns discovered paths.
    """
    base_url = host.url.rstrip("/")
    target_url = f"{base_url}/FUZZ"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = Path(tmp.name)

    log.info(f"[ffuf] Bruteforcing → {base_url}")

    cmd: list[str] = [
        "ffuf",
        "-u", target_url,
        "-w", str(wordlist_path),
        "-mc", ",".join(str(c) for c in INTERESTING_CODES),
        "-fc", FILTER_CODES,
        "-t",  str(FFUF_THREADS),
        "-timeout", str(FFUF_TIMEOUT),
        "-of", "json",
        "-o", str(output_path),
        "-s",                           # Silent mode — no banner
        "-r",                           # Follow redirects
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        log.warning(f"[ffuf] Timed out on {base_url} after 300s")
        output_path.unlink(missing_ok=True)
        return []
    except FileNotFoundError:
        log.error("[ffuf] Binary not found")
        output_path.unlink(missing_ok=True)
        return []
    except OSError as exc:
        log.error(f"[ffuf] Execution failed on {base_url}: {exc}")
        output_path.unlink(missing_ok=True)
        return []

    if result.returncode not in (0, 1):
        log.error(f"[ffuf] Exit code {result.returncode} on {base_url}")
        if result.stderr.strip():
            log.error(f"[ffuf] stderr: {result.stderr.strip()[:300]}")
        output_path.unlink(missing_ok=True)
        return []

    raw_json = ""
    try:
        if output_path.exists():
            try:
                raw_json = output_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.error(f"[ffuf] Could not read output file for {host.hostname}: {exc}")
        paths = _parse_ffuf_output(raw_json, base_url, host.hostname)
    finally:
        output_path.unlink(missing_ok=True)

    log.info(f"[ffuf] {host.hostname} → {len(paths)} path(s) found")

    for p in sorted(paths, key=lambda x: x.status_code):
        marker = " ★" if p.is_high_value else ""
        log.info(
            f"  [{p.status_code}] /{p.path:<35} "
            f"size={p.length:<8} words={p.words}{marker}"
        )

    return paths


# SAVE RESULTS
def _save_results(result: DirScanResult) -> Path:
    """Saves DirScanResult to output/directories/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name   = safe_filename(result.target)
    output_file = OUTPUT_PATH / f"{safe_name}_directories.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[ffuf] Results saved → {output_file}")
    return output_file


# MAIN ENTRY POINT
def bruteforce_directories(probe_result: ProbeResult) -> DirScanResult:
    """
    Runs ffuf directory bruteforce against every live host.
    Takes ProbeResult from Step 7.
    Returns DirScanResult with all discovered paths.
    """
    require_tools(["ffuf"])
    section(f"Directory Bruteforce → {probe_result.target}")

    scan_result = DirScanResult(target=probe_result.target)

    if not probe_result.live_hosts:
        log.warning("[ffuf] No live hosts to bruteforce — skipping")
        return scan_result

    wordlist_path = _validate_wordlist(DIR_WORDLIST)
    log.info(f"[ffuf] Wordlist: {wordlist_path}")

    for host in probe_result.live_hosts:
        paths = _run_ffuf(host, wordlist_path)

        host_result = BruteForceResult(
            hostname=host.hostname,
            base_url=host.url,
            paths=paths,
        )

        scan_result.results.append(host_result)
        if host_result.high_value_paths:
            log.warning(
                f"[ffuf] HIGH VALUE paths on {host.hostname}: "
                + ", ".join(f"/{p.path}" for p in host_result.high_value_paths)
            )

    log.info(f"[ffuf] Total paths found across all hosts: {scan_result.total_paths}")
    _save_results(scan_result)
    return scan_result