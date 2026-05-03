# modules/deduplicator.py
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from config.settings import OUTPUT_DIR
from core.logger import get_logger, section
from core.sanitize import safe_filename

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "deduplication"

# CONSTANTS

# Severity ranking — higher wins when merging duplicates
SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

# Vulnerability class normalization map
# Maps module-specific finding_type → canonical vulnerability class
# This is what enables cross-module deduplication
VULN_CLASS_MAP: dict[str, str] = {
    # XSS variants → xss
    "html_text": "xss",
    "html_attr_dq": "xss",
    "html_attr_sq": "xss",
    "html_attr_uq": "xss",
    "js_string_sq": "xss",
    "js_string_dq": "xss",
    "js_template": "xss",
    "js_bare": "xss",
    "script_block": "xss",
    "url_href": "xss",
    "xss": "xss",
    "dom_xss": "xss",

    # SQLi variants → sqli
    "error_based": "sqli",
    "boolean_based": "sqli",
    "time_based": "sqli",
    "union_based": "sqli",
    "stacked": "sqli",
    "sqli": "sqli",
    "sqli_confirmed": "sqli",

    # SSRF variants → ssrf
    "ssrf_confirmed": "ssrf",
    "ssrf_blind_oob": "ssrf",
    "ssrf_behavioral": "ssrf",
    "chain_ssrf_cloud_metadata": "ssrf",
    "ssrf": "ssrf",

    # Open redirect variants → open_redirect
    "open_redirect": "open_redirect",
    "open_redirect_javascript": "open_redirect",
    "chain_open_redirect_ssrf": "open_redirect",
    "chain_open_redirect_xss": "open_redirect",

    # Auth/IDOR variants → auth_bypass | idor
    "auth_bypass": "auth_bypass",
    "jwt_none": "auth_bypass",
    "idor_horizontal": "idor",
    "idor_vertical": "idor",
    "session_exposure": "session_exposure",
    "mass_assignment": "mass_assignment",
    "race_condition": "race_condition",
    "privilege_escalation_chain": "privilege_escalation",
}

# URL normalization — these query params are noise, strip them
NOISE_PARAMS: frozenset[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term",
    "fbclid", "gclid", "_ga", "_gl", "ref", "source",
    "timestamp", "ts", "nonce", "rand", "_", "cb",
})

# Parameters that define uniqueness of a finding
# Two findings with different values of these params = same finding
NORMALIZE_PARAM_VALUES: bool = True

# Similarity threshold for near-duplicate URL detection
# 0.0 = completely different, 1.0 = identical
URL_SIMILARITY_THRESHOLD: float = 0.80


# ── DATA MODELS ───────────────────────────────────────────────

@dataclass
class MergedFinding:
    """
    A deduplicated finding — the canonical representation of a unique vulnerability.
    May represent findings from multiple source modules.
    """
    dedup_key: str                    # Canonical key for this unique vulnerability
    vuln_class: str                    # Normalized vulnerability class
    severity: str                    # Highest severity across all sources
    url: str                    # Canonical URL (normalized)
    parameter: str | None             # Parameter name if applicable
    finding_type: str                    # Primary finding type
    title: str
    evidence: str
    confirmed: bool                   # True if any source confirmed it
    source_modules: list[str]              # Which modules found this
    source_count: int                    # How many raw findings were merged
    chain: dict[str, Any] | None  # Attack chain if present
    chain_id: str | None             # Links to related findings
    raw_findings: list[dict[str, Any]]   # Original findings for reference

    def to_dict(self) -> dict[str, Any]:
        return {
            "dedup_key": self.dedup_key,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "finding_type": self.finding_type,
            "title": self.title,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
            "source_modules": self.source_modules,
            "source_count": self.source_count,
            "chain": self.chain,
            "chain_id": self.chain_id,
        }


@dataclass
class DeduplicationStats:
    """Statistics about the deduplication run."""
    raw_total: int
    unique_total: int
    merged_count: int         # How many were merged into fewer
    by_module: dict[str, int]
    by_vuln_class: dict[str, int]
    by_severity: dict[str, int]
    chains_preserved: int

    @property
    def dedup_ratio(self) -> float:
        if self.raw_total == 0:
            return 0.0
        return round(1.0 - self.unique_total / self.raw_total, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_total": self.raw_total,
            "unique_total": self.unique_total,
            "merged_count": self.merged_count,
            "dedup_ratio": self.dedup_ratio,
            "by_module": self.by_module,
            "by_vuln_class": self.by_vuln_class,
            "by_severity": self.by_severity,
            "chains_preserved": self.chains_preserved,
        }


@dataclass
class DeduplicationResult:
    """Complete deduplication output."""
    target: str
    findings: list[MergedFinding]
    stats: DeduplicationStats
    chain_map: dict[str, list[str]]   # chain_id → [dedup_keys]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.confirmed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
            "chain_map": self.chain_map,
            "critical_count": self.critical_count,
            "confirmed_count": self.confirmed_count,
        }


# ── URL NORMALIZATION ─────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """
    Normalizes a URL for deduplication comparison.

    Operations:
    1. Lowercase scheme and host
    2. Remove default ports (80, 443)
    3. Strip noise query params (UTM, analytics)
    4. Normalize param values to placeholder when NORMALIZE_PARAM_VALUES=True
       — /user?id=1 and /user?id=2 become /user?id=NORM
    5. Remove trailing slashes from path
    6. Sort remaining query params for consistent ordering

    Why: Two findings on /api/user?id=1 and /api/user?id=99
    are the same vulnerability — different parameter values, same injection point.
    """
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return url.lower().strip()

    # Normalize host and scheme
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port

    # Strip default ports
    netloc = host
    if port and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        netloc = f"{host}:{port}"

    # Normalize path
    path = parsed.path.rstrip("/") or "/"

    # Normalize query params
    raw_params = parse_qs(parsed.query, keep_blank_values=False)
    clean_params: dict[str, str] = {}

    for key, values in sorted(raw_params.items()):
        if key.lower() in NOISE_PARAMS:
            continue
        if NORMALIZE_PARAM_VALUES:
            clean_params[key] = "NORM"
        else:
            clean_params[key] = values[0] if values else ""

    normalized_query = urlencode(sorted(clean_params.items()))
    normalized = urlunparse((scheme, netloc, path, "", normalized_query, ""))
    return normalized


def _url_similarity(url_a: str, url_b: str) -> float:
    """
    Computes structural similarity between two normalized URLs.
    Uses path segment Jaccard similarity.

    Why path segments and not full string: /api/v1/users/123 and /api/v1/users/456
    should be ~1.0 similar — same endpoint, different ID.
    Full string edit distance would score these as different.
    """
    def _path_segments(url: str) -> set[str]:
        path = urlparse(url).path
        return {seg for seg in path.split("/") if seg and not seg.isdigit()}

    segs_a = _path_segments(url_a)
    segs_b = _path_segments(url_b)

    if not segs_a and not segs_b:
        return 1.0

    union = segs_a | segs_b
    intersection = segs_a & segs_b
    return len(intersection) / len(union) if union else 1.0


# FINDING NORMALIZATION

def _get_vuln_class(finding: dict[str, Any]) -> str:
    """
    Maps finding_type to canonical vulnerability class.
    Falls back to the raw finding_type if unmapped.
    """
    raw_type = str(
        finding.get("finding_type")
        or finding.get("technique")
        or finding.get("type")
        or "unknown"
    ).lower()

    return VULN_CLASS_MAP.get(raw_type, raw_type)


def _get_severity(finding: dict[str, Any]) -> str:
    """Extracts normalized severity string."""
    return str(finding.get("severity", "unknown")).lower()


def _get_parameter(finding: dict[str, Any]) -> str | None:
    """Extracts parameter name from finding dict."""
    return (
        finding.get("parameter")
        or finding.get("param")
        or finding.get("param_name")
    )


def _is_confirmed(finding: dict[str, Any]) -> bool:
    """Returns True if finding is confirmed by any signal."""
    return bool(
        finding.get("is_confirmed")
        or finding.get("executed")
        or finding.get("oob_hit")
        or finding.get("confirmed")
        or finding.get("severity", "").lower() == "critical"
    )


def _get_module(finding: dict[str, Any]) -> str:
    """Infers which module produced this finding."""
    finding_type = str(finding.get("finding_type") or finding.get("technique") or "")
    url          = str(finding.get("url", ""))

    vuln_class = _get_vuln_class(finding)
    module_map = {
        "xss": "xss_scanner",
        "sqli": "sqli_scanner",
        "ssrf": "ssrf_redirect",
        "open_redirect": "ssrf_redirect",
        "auth_bypass": "broken_auth_idor",
        "idor": "broken_auth_idor",
        "session_exposure": "broken_auth_idor",
        "mass_assignment": "broken_auth_idor",
        "race_condition": "broken_auth_idor",
        "privilege_escalation": "broken_auth_idor",
    }
    return module_map.get(vuln_class, finding.get("module", "unknown"))


def _get_chain(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Extracts chain data from finding."""
    chain = finding.get("chain")
    if isinstance(chain, dict):
        return chain
    return None


def _get_chain_id(finding: dict[str, Any]) -> str | None:
    return finding.get("chain_id") or finding.get("chain_source")


def _get_title(finding: dict[str, Any]) -> str:
    """Extracts or generates a title for the finding."""
    if finding.get("title"):
        return str(finding["title"])
    vuln_class = _get_vuln_class(finding)
    url = finding.get("url", "unknown")
    param = _get_parameter(finding)
    param_str = f" ?{param}" if param else ""
    return f"{vuln_class.upper()} — {url}{param_str}"


def _get_evidence(finding: dict[str, Any]) -> str:
    """Extracts evidence string, truncated."""
    evidence = finding.get("evidence", "")
    if isinstance(evidence, dict):
        evidence = json.dumps(evidence)
    return str(evidence)[:500]


# DEDUP KEY GENERATION

def _make_exact_key(
    vuln_class: str,
    norm_url: str,
    parameter: str | None,
) -> str:
    """
    Generates exact deduplication key.
    Two findings with the same key = definitely the same vulnerability.

    Key components: vuln_class + normalized_url + parameter_name
    Parameter value is NOT included — /user?id=1 and /user?id=2 = same key.
    """
    raw = f"{vuln_class}::{norm_url}::{parameter or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]



# MERGE ENGINE
def _merge_group(findings: list[dict[str, Any]]) -> MergedFinding:
    """
    Merges a group of duplicate findings into one canonical MergedFinding.

    Merge rules:
    - Severity: highest wins
    - Confirmed: True if ANY source confirmed it
    - Evidence: from the highest-severity source
    - Chain: preserved if any source has one
    - Title: from the highest-severity source
    - source_modules: union of all modules that found this
    """
    # Sort by severity descending — primary finding is highest severity
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(_get_severity(f), 0),
            int(_is_confirmed(f)),
        ),
        reverse=True,
    )

    primary = sorted_findings[0]
    vuln_class = _get_vuln_class(primary)
    norm_url = _normalize_url(primary.get("url", ""))
    parameter = _get_parameter(primary)

    # Highest severity across all merged findings
    best_severity = max(
        (_get_severity(f) for f in sorted_findings),
        key=lambda s: SEVERITY_RANK.get(s, 0),
    )

    # Confirmed if any source confirmed it
    any_confirmed = any(_is_confirmed(f) for f in sorted_findings)

    # Chain: prefer confirmed chain over null
    chain    = next((_get_chain(f) for f in sorted_findings if _get_chain(f)), None)
    chain_id = next((_get_chain_id(f) for f in sorted_findings if _get_chain_id(f)), None)

    # Source modules: unique set preserving order
    seen_modules: set[str]   = set()
    source_modules: list[str] = []
    for f in sorted_findings:
        mod = _get_module(f)
        if mod not in seen_modules:
            seen_modules.add(mod)
            source_modules.append(mod)

    dedup_key = _make_exact_key(vuln_class, norm_url, parameter)

    return MergedFinding(
        dedup_key=dedup_key,
        vuln_class=vuln_class,
        severity=best_severity,
        url=norm_url,
        parameter=parameter,
        finding_type=str(
            primary.get("finding_type")
            or primary.get("technique")
            or vuln_class
        ),
        title=_get_title(primary),
        evidence=_get_evidence(primary),
        confirmed=any_confirmed,
        source_modules=source_modules,
        source_count=len(sorted_findings),
        chain=chain,
        chain_id=chain_id,
        raw_findings=sorted_findings,
    )


# NEAR-DUPLICATE DETECTOR

def _group_near_duplicates(
    findings: list[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    """
    Groups findings into exact and near-duplicate clusters.

    Algorithm:
    1. Exact match: same dedup_key (vuln_class + normalized_url + param)
    2. Near-duplicate: same vuln_class + URL path similarity > threshold

    Near-duplicate detection catches:
    - /api/v1/users/1 and /api/v1/users/2 (same endpoint, different IDs)
    - http vs https variants of same URL
    - With/without trailing slash variants
    - Same injection point found by multiple modules

    Returns list of groups — each group becomes one MergedFinding.
    """
    # Build exact-key groups first
    exact_groups: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        vuln_class = _get_vuln_class(finding)
        norm_url = _normalize_url(finding.get("url", ""))
        parameter = _get_parameter(finding)
        key = _make_exact_key(vuln_class, norm_url, parameter)

        exact_groups.setdefault(key, []).append(finding)

    # Now merge near-duplicates across exact groups
    # Use union-find for efficient grouping
    group_keys = list(exact_groups.keys())
    parent: dict[str, str] = {k: k for k in group_keys}

    def _find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # Path compression
            x = parent[x]
        return x

    def _union(x: str, y: str) -> None:
        px, py = _find(x), _find(y)
        if px != py:
            parent[py] = px

    # Check each pair of exact groups for near-duplicate URL similarity
    # Only compare within same vuln_class — different bug types are never duplicates
    class_to_keys: dict[str, list[str]] = {}
    for key in group_keys:
        first_finding = exact_groups[key][0]
        vc = _get_vuln_class(first_finding)
        class_to_keys.setdefault(vc, []).append(key)

    for vc, keys in class_to_keys.items():
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                key_a = keys[i]
                key_b = keys[j]

                # Skip if already in same group
                if _find(key_a) == _find(key_b):
                    continue

                # Compare URL similarity
                url_a = _normalize_url(exact_groups[key_a][0].get("url", ""))
                url_b = _normalize_url(exact_groups[key_b][0].get("url", ""))

                # Also check parameter match — same param = stronger signal
                param_a = _get_parameter(exact_groups[key_a][0])
                param_b = _get_parameter(exact_groups[key_b][0])
                params_match = (param_a == param_b) or (param_a is None and param_b is None)

                sim = _url_similarity(url_a, url_b)
                if sim >= URL_SIMILARITY_THRESHOLD and params_match:
                    _union(key_a, key_b)

    # Collect final groups
    root_to_keys: dict[str, list[str]] = {}
    for key in group_keys:
        root = _find(key)
        root_to_keys.setdefault(root, []).append(key)

    # Flatten into finding groups
    result: list[list[dict[str, Any]]] = []
    for root, keys in root_to_keys.items():
        group: list[dict[str, Any]] = []
        for key in keys:
            group.extend(exact_groups[key])
        result.append(group)

    return result


# CHAIN CORRELATION

def _build_chain_map(
    merged_findings: list[MergedFinding],
) -> dict[str, list[str]]:
    """
    Builds a chain correlation map: chain_id → [dedup_keys].
    Preserves attack chain relationships across merged findings.
    Used by reporting modules to display attack chains correctly.
    """
    chain_map: dict[str, list[str]] = {}
    for finding in merged_findings:
        if finding.chain_id:
            chain_map.setdefault(finding.chain_id, []).append(finding.dedup_key)
    return chain_map


# STATISTICS

def _compute_stats(
    raw_findings: list[dict[str, Any]],
    merged_findings: list[MergedFinding],
) -> DeduplicationStats:
    """Computes deduplication statistics for reporting."""
    by_module: dict[str, int] = {}
    by_vuln_class: dict[str, int] = {}
    by_severity:   dict[str, int] = {}

    for f in merged_findings:
        for mod in f.source_modules:
            by_module[mod] = by_module.get(mod, 0) + 1
        vc = f.vuln_class
        by_vuln_class[vc] = by_vuln_class.get(vc, 0) + 1
        sev = f.severity
        by_severity[sev] = by_severity.get(sev, 0) + 1

    chains_preserved = sum(1 for f in merged_findings if f.chain is not None)
    merged_count = sum(f.source_count - 1 for f in merged_findings if f.source_count > 1)

    return DeduplicationStats(
        raw_total=len(raw_findings),
        unique_total=len(merged_findings),
        merged_count=merged_count,
        by_module=dict(sorted(by_module.items(), key=lambda x: x[1], reverse=True)),
        by_vuln_class=dict(sorted(by_vuln_class.items(), key=lambda x: x[1], reverse=True)),
        by_severity=dict(sorted(by_severity.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True)),
        chains_preserved=chains_preserved,
    )


# SAVE

def _save_results(result: DeduplicationResult) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe = safe_filename(result.target)
    out_file = OUTPUT_PATH / f"{safe}_deduplicated.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
    log.info(f"[Dedup] Results saved → {out_file}")
    return out_file


# MAIN ENTRY POINT

def deduplicate_findings(
    target: str,
    raw_findings: list[dict[str, Any]],
) -> DeduplicationResult:
    """
    Deduplicates all findings from all PHANTOM scan modules.

    Three-tier deduplication:
    1. Exact match — same vuln_class + normalized URL + parameter name
    2. Near-duplicate — same vuln_class + URL path similarity above threshold
    3. Chain preservation — attack chains maintained across merged findings

    Merge rules:
    - Severity: highest wins (critical > high > medium > low > info)
    - Confirmed: True if any source confirmed it
    - Source modules: union of all modules that independently found it
    - Chain: preserved if any source has one

    Args:
        target:       Target domain.
        raw_findings: All findings from all modules as list of dicts.

    Returns:
        DeduplicationResult with clean unique finding set.
    """
    section(f"Deduplication Engine → {target}")

    if not raw_findings:
        log.info("[Dedup] No findings to deduplicate")
        empty_stats = DeduplicationStats(
            raw_total=0, unique_total=0, merged_count=0,
            by_module={}, by_vuln_class={}, by_severity={}, chains_preserved=0,
        )
        return DeduplicationResult(
            target=target, findings=[], stats=empty_stats, chain_map={}
        )

    log.info(f"[Dedup] Raw findings: {len(raw_findings)}")

    # Group into duplicate clusters
    groups = _group_near_duplicates(raw_findings)
    log.info(f"[Dedup] Groups after clustering: {len(groups)}")

    # Merge each group into a single canonical finding
    merged: list[MergedFinding] = [_merge_group(group) for group in groups]

    # Sort: confirmed critical first, then by severity
    merged.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 0),
            int(f.confirmed),
        ),
        reverse=True,
    )

    # Build chain correlation map
    chain_map = _build_chain_map(merged)

    # Compute statistics
    stats = _compute_stats(raw_findings, merged)

    log.info(f"[Dedup] Unique findings: {stats.unique_total} (dedup ratio: {stats.dedup_ratio:.0%})")
    log.info(f"[Dedup] Merged {stats.merged_count} duplicate(s)")
    log.info(f"[Dedup] Chains preserved: {stats.chains_preserved}")
    log.info(f"[Dedup] By severity: {stats.by_severity}")
    log.info(f"[Dedup] By vuln class: {stats.by_vuln_class}")

    result = DeduplicationResult(
        target=target,
        findings=merged,
        stats=stats,
        chain_map=chain_map,
    )

    _save_results(result)
    return result