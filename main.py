from __future__ import annotations

import sys
import typer
from pathlib import Path
from typing import Annotated

from core.logger import get_logger, print_banner, section
from core.config_loader import init_dirs, load_targets
from core.tool_checker import check_all_tools
from config.settings import TARGETS_FILE
from modules.subdomain_enum import enumerate_subdomains, SubdomainResult
from modules.host_probe import probe_live_hosts, ProbeResult
from modules.port_scanner import scan_ports, PortScanResult
from modules.tech_fingerprint import fingerprint_technologies, TechScanResult
from modules.wayback_harvest import harvest_wayback_urls, WaybackResult
from modules.dir_bruteforce import bruteforce_directories, DirScanResult
from modules.js_analyzer import analyze_javascript, JSAnalysisResult
from modules.param_discovery import discover_parameters, ParamScanResult
from modules.xss_scanner import scan_xss, XSSScanResult
from modules.xss_verifier import verify_xss_findings, VerifierReport
from modules.sqli_scanner import scan_sqli, SQLiScanResult
from modules.ssrf_redirect import scan_ssrf_redirect, SSRFRedirectResult
from modules.broken_auth_idor import scan_broken_auth_idor, AuthScanResult
from modules.ai_brain import (
    create_scan_state, ai_decision, ai_triage,
    check_and_escalate, AnalysisPhase, ScanState,
)
from modules.deduplicator import deduplicate_findings, DeduplicationResult

app = typer.Typer(
    name="phantom",
    help="PHANTOM — Web App VAPT Automation Framework",
    add_completion=False,
)

log = get_logger()

class PhantomError(RuntimeError):
    """Base exception for PHANTOM runtime failures."""


def _run_step(step_name: str, fallback, func, *args, **kwargs):
    """Run one pipeline step and return fallback on module/tool failure."""
    try:
        return func(*args, **kwargs)
    except RuntimeError as exc:
        log.warning(f"[PIPELINE] Skipping {step_name}: {exc}")
    except Exception as exc:
        log.error(f"[PIPELINE] {step_name} failed: {exc}")
    return fallback

# startup routine
def _bootstrap() -> None:
    """Initialize dirs, verify tools. Raises PhantomError on failure."""
    init_dirs()

    results = check_all_tools()
    missing = [t for t, ok in results.items() if not ok]

    if missing:
        log.warning(f"Missing tools: {', '.join(missing)}")
        log.warning("Some modules will be skipped. Install missing tools to unlock full scan.")

# Commands
@app.command()
def scan(
    target: Annotated[str | None, typer.Option(
        "--target", "-t",
        help="Single target domain (e.g. example.com)"
    )] = None,
    targets_file: Annotated[Path, typer.Option(
        "--file", "-f",
        help="Path to targets file (default: config/targets.txt)"
    )] = Path(TARGETS_FILE),
    check_only: Annotated[bool, typer.Option(
        "--check-only",
        help="Only run tool checks, do not scan"
    )] = False,
) -> None:
    """Run full VAPT scan against one or more targets."""
    print_banner()
    _bootstrap()

    if check_only:
        log.info("--check-only flag set. Exiting after tool check.")
        raise typer.Exit(0)
    
    targets: list[str] = []

    if target:
        targets = [target.strip()]
        log.info(f"Single target: {target}")
    else:
        try:
            targets = load_targets(str(targets_file))
            log.info(f"Loaded {len(targets)} target(s) from {targets_file}")
        except (FileNotFoundError, ValueError) as e:
            log.error(str(e))
            raise typer.Exit(1)

    # ── Scan pipeline (modules plug in here from Step 6+) ────
    section("Scan Pipeline")
    for t in targets:
        log.info(f"Target → {t}")
        _run_pipeline(t)

def _run_pipeline(target: str) -> None:
    log.info(f"[PIPELINE] Starting scan: {target}")
    state = create_scan_state(target)

    # Subdomain Enumeration
    subdomain_result = _run_step(
        "Subdomain Enumeration",
        SubdomainResult(target=target),
        enumerate_subdomains,
        target,
    )
    log.info(f"[PIPELINE] Subdomains found: {subdomain_result.count}")

    # Live Host Detection
    probe_result = _run_step(
        "Live Host Detection",
        ProbeResult(target=target),
        probe_live_hosts,
        subdomain_result,
    )
    log.info(f"[PIPELINE] Live hosts: {probe_result.count}")

    # Port Scanning
    port_result = _run_step(
        "Port Scanning",
        PortScanResult(target=target),
        scan_ports,
        probe_result,
    )
    log.info(f"[PIPELINE] Open ports: {port_result.total_open_ports}")

    # Technology Fingerprinting
    tech_result = _run_step(
        "Technology Fingerprinting",
        TechScanResult(target=target),
        fingerprint_technologies,
        probe_result,
    )
    log.info(f"[PIPELINE] Hosts fingerprinted: {len(tech_result.results)}")

    # Wayback URL Harvesting
    wayback_result = _run_step(
        "Wayback URL Harvesting",
        WaybackResult(target=target),
        harvest_wayback_urls,
        target,
    )
    log.info(f"[PIPELINE] Wayback URLs: {wayback_result.total_urls}")

    # Directory Bruteforce
    dir_result = _run_step(
        "Directory Bruteforce",
        DirScanResult(target=target),
        bruteforce_directories,
        probe_result,
    )
    log.info(f"[PIPELINE] Paths found: {dir_result.total_paths}")

    # JavaScript Analysis
    js_result = _run_step(
        "JavaScript Analysis",
        JSAnalysisResult(target=target),
        analyze_javascript,
        probe_result,
    )
    log.info(f"[PIPELINE] JS secrets: {js_result.total_secrets}")
    log.info(f"[PIPELINE] JS endpoints: {len(set(js_result.all_endpoints))}")

    # Parameter Discovery
    param_result = _run_step(
        "Parameter Discovery",
        ParamScanResult(target=target),
        discover_parameters,
        probe_result,
        wayback_result,
        js_result,
    )
    log.info(f"[PIPELINE] Parameters found: {param_result.total_params}")
    log.info(f"[PIPELINE] Injectable URLs:  {len(param_result.injectable_urls)}")

    # XSS Scanner
    xss_result = _run_step(
        "XSS Scanner",
        XSSScanResult(target=target),
        scan_xss,
        probe_result,
        param_result,
    )
    log.info(f"[PIPELINE] XSS confirmed: {xss_result.confirmed_count}")
    log.info(f"[PIPELINE] DOM findings:  {len(xss_result.dom_findings)}")

    # Playwright XSS Execution Verification
    xss_verified = _run_step(
        "XSS Execution Verification",
        VerifierReport(target=target),
        verify_xss_findings,
        xss_result.to_dict(),
        target,
    )
    log.info(f"[PIPELINE] XSS executed in browser: {xss_verified.executed_count}")

    # SQLi Scanner
    sqli_result = _run_step(
        "SQLi Scanner",
        SQLiScanResult(target=target),
        scan_sqli,
        probe_result,
        param_result,
        # exploit_mode=True  ← uncomment for full SQLMap exploitation
    )

    # SSRF + Open Redirect
    ssrf_result = _run_step(
        "SSRF + Open Redirect",
        SSRFRedirectResult(target=target),
        scan_ssrf_redirect,
        probe_result,
        param_result,
    )
    log.info(f"[PIPELINE] SSRF findings: {len(ssrf_result.findings)}")
    log.info(f"[PIPELINE] Attack chains: {ssrf_result.chain_count}")

    # Broken Auth + IDOR
    auth_result = _run_step(
        "Broken Auth + IDOR",
        AuthScanResult(target=target),
        scan_broken_auth_idor,
        probe_result,
        param_result,
        js_result,
    )
    log.info(f"[PIPELINE] Auth findings: {auth_result.confirmed_count}")
    log.info(f"[PIPELINE] Attack chains: {len(auth_result.chain_opportunities)}")

    # Collect findings for legacy main.py state
    for res in [xss_result, sqli_result, ssrf_result, auth_result]:
        if hasattr(res, "findings") and getattr(res, "findings"):
            state.all_findings.extend(res.findings)

    # After all scanning + AI triage — before reporting
    # Add all findings to state first (already done via check_and_escalate)
    # Then deduplicate:

    dedup_result = deduplicate_findings(
        target=target,
        raw_findings=state.all_findings,
    )
    log.info(f"[PIPELINE] Unique findings: {dedup_result.stats.unique_total}")
    log.info(f"[PIPELINE] Dedup ratio:     {dedup_result.stats.dedup_ratio:.0%}")
    log.info(f"[PIPELINE] Critical:        {dedup_result.critical_count}")

    log.info(f"[PIPELINE] Scan complete: {target}")
    

@app.command()
def version() -> None:
    """Show PHANTOM version."""
    typer.echo("PHANTOM v1.0.0 — VAPT Automator")

if __name__ == "__main__":
    app()