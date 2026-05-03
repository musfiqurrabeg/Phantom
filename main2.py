"""
PHANTOM — Web App VAPT Automation Framework
main.py  ·  Orchestration Layer v2.1

Bug fixes (self-audit):
  BUG 1 [CRITICAL] — Eager fallback evaluation: create_scan_state(target) was
    passed as the fallback arg to _run_step, which evaluates it immediately at
    call time — before _run_step runs. If create_scan_state raises, _run_step
    never had a chance to catch it. Fixed: call create_scan_state directly under
    try/except instead of routing through _run_step.

  BUG 2 [HIGH] — xss_result.to_dict() called bare outside _run_step on the
    playwright path. If to_dict() throws, it crashes the pipeline with no handler.
    Fixed: routed through _safe_dict() helper.

  BUG 3 [HIGH] — ai_decision/ai_triage/check_and_escalate called with positional
    args. Without seeing the actual module signatures, positional args are an
    assumption that breaks silently (wrong arg mapped to wrong param). Reverted
    to kwargs, which match the original v1 calling convention.

  BUG 4 [MEDIUM] — state.should_run_module() called unconditionally but if
    create_scan_state failed and returned a plain ScanState fallback, the method
    may not exist. Fixed: _should_run() helper wraps the call with hasattr guard,
    defaulting to True (run everything) on AttributeError.

  BUG 5 [MEDIUM] — Partial scan failure (some targets failed, some succeeded)
    exited with code 0. Fixed: exit 1 for partial failure, 2 for total failure.

  BUG 6 [LOW] — `import sys` present but sys is never referenced. Removed.

  BUG 7 [LOW] — SQLi finding count called _safe_findings() twice and used the
    .__len__() antipattern instead of len(). Fixed: single assignment + len().

  BUG 8 [LOW] — Signal handlers registered at module import time (module-level
    side effect). This registers SIGINT/SIGTERM handlers even when the module is
    imported in tests or other tools. Moved into scan() so they only register
    when the CLI command actually runs.
"""

from __future__ import annotations

import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from config.settings import TARGETS_FILE
from core.config_loader import init_dirs, load_targets
from core.logger import get_logger, print_banner, section
from core.sanitize import validate_target
from core.tool_checker import check_all_tools
from modules.ai_brain import (
    AnalysisPhase,
    ScanState,
    ai_decision,
    ai_triage,
    check_and_escalate,
    create_scan_state,
)
from modules.broken_auth_idor import AuthScanResult, scan_broken_auth_idor
from modules.dir_bruteforce import DirScanResult, bruteforce_directories
from modules.host_probe import ProbeResult, probe_live_hosts
from modules.js_analyzer import JSAnalysisResult, analyze_javascript
from modules.param_discovery import ParamScanResult, discover_parameters
from modules.port_scanner import PortScanResult, scan_ports
from modules.sqli_scanner import SQLiScanResult, scan_sqli
from modules.ssrf_redirect import SSRFRedirectResult, scan_ssrf_redirect
from modules.subdomain_enum import SubdomainResult, enumerate_subdomains
from modules.tech_fingerprint import TechScanResult, fingerprint_technologies
from modules.wayback_harvest import WaybackResult, harvest_wayback_urls
from modules.xss_scanner import XSSScanResult, scan_xss
from modules.xss_verifier import VerifierReport, verify_xss_findings

# App setup
app = typer.Typer(
    name="phantom",
    help="PHANTOM — Web App VAPT Automation Framework",
    add_completion=False,
)
log = get_logger()

# Exceptions
class PhantomError(RuntimeError):
    """Base exception for PHANTOM runtime failures."""

# Shutdown flag
# NOTE: signal handlers are NOT registered here (module-level side effect — BUG 8).
# They are registered inside scan() so tests and imports are unaffected.
_shutdown_requested = False

def _handle_signal(signum: int, _frame: Any) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    log.warning(
        f"[PHANTOM] Signal {signum} received — "
        "finishing current step then exiting cleanly."
    )


# Pipeline step runner
def _run_step(step_name: str, fallback: Any, func, *args, **kwargs) -> Any:
    """
    Execute one pipeline step.

    - Returns the step result on success.
    - Returns *fallback* on RuntimeError (expected tool/module failure).
    - Returns *fallback* on any Exception and logs an error (unexpected failure).
    - Never raises — the pipeline always continues.

    IMPORTANT: *fallback* is evaluated by the caller before this function runs.
    Never pass a function call as fallback if that call itself might raise —
    that evaluation happens before _run_step can protect it (BUG 1 pattern).
    Use a pre-constructed default object instead.
    """
    if _shutdown_requested:
        log.warning(f"[PIPELINE] Skipping {step_name} — shutdown requested.")
        return fallback
    try:
        return func(*args, **kwargs)
    except RuntimeError as exc:
        log.warning(f"[PIPELINE] Skipping {step_name}: {exc}")
    except Exception as exc:  # noqa: BLE001
        log.error(f"[PIPELINE] {step_name} failed unexpectedly: {exc}", exc_info=True)
    return fallback


# Bootstrap 
def _bootstrap() -> set[str]:
    """
    Initialise output dirs and verify required tools.

    Returns:
        Set of tool names that are *missing* (empty set = fully equipped).
    Raises:
        PhantomError: if directory initialisation itself fails.
    """
    try:
        init_dirs()
    except Exception as exc:  # noqa: BLE001
        raise PhantomError(f"Failed to initialise working directories: {exc}") from exc

    results = check_all_tools()
    missing: set[str] = {t for t, ok in results.items() if not ok}

    if missing:
        log.warning(f"[BOOTSTRAP] Missing tools: {', '.join(sorted(missing))}")
        log.warning("[BOOTSTRAP] Affected modules will be skipped automatically.")
    else:
        log.info("[BOOTSTRAP] All tools present.")

    return missing


# Reporting
@dataclass
class ScanReport:
    target: str
    errors: list[str] = field(default_factory=list)
    findings_by_module: dict[str, int] = field(default_factory=dict)
    overall_risk: str = "unknown"
    writeup_count: int = 0
    escalation_count: int = 0
    ai_tokens: int = 0
    ai_latency_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return sum(self.findings_by_module.values())


def _print_report(report: ScanReport) -> None:
    section(f"Scan Report — {report.target}")
    log.info(f"  Overall risk     : {report.overall_risk.upper()}")
    log.info(f"  Total findings   : {report.total_findings}")
    for mod, count in report.findings_by_module.items():
        if count:
            log.info(f"    {mod:<28}: {count}")
    log.info(f"  Writeups ready   : {report.writeup_count}")
    log.info(f"  Escalations fired: {report.escalation_count}")
    log.info(f"  AI tokens used   : {report.ai_tokens}")
    log.info(f"  AI latency       : {report.ai_latency_ms:.0f} ms")
    if report.errors:
        log.warning(f"  Non-fatal errors : {len(report.errors)}")
        for e in report.errors:
            log.warning(f"    • {e}")


# Safe helpers
def _safe_findings(result: Any, dict_key: str = "findings") -> list:
    """
    Extract a findings list from any module result safely.
    Handles: result is None, to_dict() raises, dict_key absent.
    """
    if result is None:
        return []
    try:
        d = result.to_dict()
        return d.get(dict_key, []) or []
    except Exception:  # noqa: BLE001
        return []


def _safe_dict(result: Any) -> dict:
    """
    Call result.to_dict() safely, returning {} on any failure.
    Prevents BUG 2: bare .to_dict() calls crashing outside _run_step.
    """
    if result is None:
        return {}
    try:
        return result.to_dict() or {}
    except Exception:  # noqa: BLE001
        return {}


def _should_run(state: ScanState, module_name: str) -> bool:
    """
    Safely call state.should_run_module().
    Defaults to True (run the module) if the method doesn't exist — e.g. when a
    fallback plain ScanState was returned by _run_step and should_run_module was
    never populated. Prevents BUG 4: AttributeError on vanilla ScanState fallback.
    """
    try:
        return bool(state.should_run_module(module_name))
    except AttributeError:
        log.debug(
            f"[PIPELINE] state.should_run_module not available "
            f"— defaulting to run {module_name}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning(
            f"[PIPELINE] should_run_module({module_name}) raised: {exc} "
            "— defaulting to run"
        )
        return True


# Per-target pipeline
def _run_pipeline(target: str, missing_tools: set[str]) -> ScanReport:
    """
    Full VAPT pipeline for a single target.

    Every module call is wrapped in _run_step so one failure never kills the scan.
    Tool-gating uses both ai_brain.should_run_module AND the missing_tools set.
    Returns a ScanReport with aggregated results.
    """
    report = ScanReport(target=target)
    log.info(f"[PIPELINE] Starting: {target}")

    # Tool gate helper
    def tool_ok(*required_tools: str) -> bool:
        """Return False and log if any required tool is missing."""
        blocked = [t for t in required_tools if t in missing_tools]
        if blocked:
            log.info(f"[PIPELINE] Skipping — missing tool(s): {', '.join(blocked)}")
            return False
        return True

    # ── Create AI brain state — BUG 1 FIX ────────────────────────────────
    # DO NOT route through _run_step with create_scan_state(target) as fallback.
    # Fallback args are evaluated eagerly at call time; if create_scan_state raises,
    # the exception fires before _run_step can catch it. Handle directly.
    try:
        state: ScanState = create_scan_state(target)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"[PIPELINE] AI Brain Init failed: {exc} — proceeding with default state")
        state = ScanState(target=target)

    # RECON
    section(f"Recon — {target}")
    subdomain_result: SubdomainResult = _run_step(
        "Subdomain Enumeration",
        SubdomainResult(target=target),
        enumerate_subdomains,
        target,
    )
    log.info(f"[RECON] Subdomains found: {subdomain_result.count}")

    probe_result: ProbeResult = _run_step(
        "Live Host Detection",
        ProbeResult(target=target),
        probe_live_hosts,
        subdomain_result,
    )
    log.info(f"[RECON] Live hosts: {probe_result.count}")

    port_result: PortScanResult = _run_step(  # noqa: F841  (used by future modules)
        "Port Scanning",
        PortScanResult(target=target),
        scan_ports,
        probe_result,
    )
    log.info(f"[RECON] Open ports: {port_result.total_open_ports}")

    tech_result: TechScanResult = _run_step(
        "Technology Fingerprinting",
        TechScanResult(target=target),
        fingerprint_technologies,
        probe_result,
    )
    log.info(f"[RECON] Hosts fingerprinted: {len(tech_result.results)}")

    wayback_result: WaybackResult = _run_step(
        "Wayback URL Harvesting",
        WaybackResult(target=target),
        harvest_wayback_urls,
        target,
    )
    log.info(f"[RECON] Wayback URLs: {wayback_result.total_urls}")

    # Serialise tech for AI brain — _safe_dict never raises (BUG 2 pattern)
    tech_dict: dict = _safe_dict(tech_result)

    # AI Decision 1: Post-Recon — BUG 3 FIX (kwargs)
    state = _run_step(
        "AI Decision (Post-Recon)",
        state,
        ai_decision,
        state=state,
        phase=AnalysisPhase.POST_RECON,
        tech_result=tech_dict,
        available_modules=[
            "dir_bruteforce", "js_analyzer", "param_discovery",
            "xss_scanner", "sqli_scanner", "ssrf_redirect",
            "broken_auth_idor", "nuclei", "cve_lookup",
        ],
    )

    # SCANNING
    section(f"Scanning — {target}")

    # Directory Bruteforce — BUG 4 FIX: _should_run instead of bare .should_run_module
    dir_result: Optional[DirScanResult] = None
    if _should_run(state, "dir_bruteforce") and tool_ok("ffuf"):
        dir_result = _run_step(
            "Directory Bruteforce",
            DirScanResult(target=target),
            bruteforce_directories,
            probe_result,
        )
        if dir_result:
            log.info(f"[SCAN] Paths found: {dir_result.total_paths}")
            report.findings_by_module["dir_bruteforce"] = dir_result.total_paths

    # JavaScript Analysis
    js_result: Optional[JSAnalysisResult] = None
    if _should_run(state, "js_analyzer"):
        js_result = _run_step(
            "JavaScript Analysis",
            None,
            analyze_javascript,
            probe_result,
        )
        if js_result:
            log.info(f"[SCAN] JS secrets  : {js_result.total_secrets}")
            log.info(f"[SCAN] JS endpoints: {len(set(js_result.all_endpoints))}")
            report.findings_by_module["js_analyzer"] = js_result.total_secrets

    # Parameter Discovery — js_result may be None; module must handle it
    param_result: ParamScanResult = _run_step(
        "Parameter Discovery",
        ParamScanResult(target=target),
        discover_parameters,
        probe_result,
        wayback_result,
        js_result,
    )
    log.info(f"[SCAN] Parameters found: {param_result.total_params}")
    log.info(f"[SCAN] Injectable URLs : {len(param_result.injectable_urls)}")

    # XSS Scanner
    xss_result: Optional[XSSScanResult] = None
    if _should_run(state, "xss_scanner"):
        xss_result = _run_step(
            "XSS Scanner",
            None,
            scan_xss,
            probe_result,
            param_result,
        )
        if xss_result:
            log.info(f"[SCAN] XSS confirmed: {xss_result.confirmed_count}")
            log.info(f"[SCAN] DOM findings : {len(xss_result.dom_findings)}")
            report.findings_by_module["xss_scanner"] = xss_result.confirmed_count

            state = _run_step(
                "AI Escalation (XSS)",
                state,
                check_and_escalate,
                state=state,
                findings=_safe_findings(xss_result),
            )

            # XSS Execution Verification — BUG 2 FIX:
            # Was: verify_xss_findings(xss_result.to_dict(), target)
            # .to_dict() was bare — if it raised, the crash was outside _run_step.
            # Fix: route through _safe_dict() which never raises.
            if tool_ok("playwright"):
                _run_step(
                    "XSS Execution Verification",
                    VerifierReport(target=target),
                    verify_xss_findings,
                    _safe_dict(xss_result),
                    target,
                )

    # SQLi Scanner — BUG 7 FIX: assign findings once, use len() not .__len__()
    sqli_result: Optional[SQLiScanResult] = None
    if _should_run(state, "sqli_scanner") and tool_ok("sqlmap"):
        sqli_result = _run_step(
            "SQLi Scanner",
            None,
            scan_sqli,
            probe_result,
            param_result,
            exploit_mode=state.is_exploit_mode,
        )
        if sqli_result:
            sqli_findings = _safe_findings(sqli_result)
            log.info(f"[SCAN] SQLi findings: {len(sqli_findings)}")
            report.findings_by_module["sqli_scanner"] = len(sqli_findings)

            state = _run_step(
                "AI Escalation (SQLi)",
                state,
                check_and_escalate,
                state=state,
                findings=sqli_findings,
            )

    # SSRF + Open Redirect
    ssrf_result: Optional[SSRFRedirectResult] = None
    if _should_run(state, "ssrf_redirect"):
        ssrf_result = _run_step(
            "SSRF + Open Redirect",
            None,
            scan_ssrf_redirect,
            probe_result,
            param_result,
        )
        if ssrf_result:
            log.info(f"[SCAN] SSRF findings : {len(ssrf_result.findings)}")
            log.info(f"[SCAN] Attack chains : {ssrf_result.chain_count}")
            report.findings_by_module["ssrf_redirect"] = len(ssrf_result.findings)

            state = _run_step(
                "AI Escalation (SSRF)",
                state,
                check_and_escalate,
                state=state,
                findings=_safe_findings(ssrf_result),
            )

    # Broken Auth + IDOR
    auth_result: Optional[AuthScanResult] = None
    if _should_run(state, "broken_auth_idor"):
        auth_result = _run_step(
            "Broken Auth + IDOR",
            None,
            scan_broken_auth_idor,
            probe_result,
            param_result,
            js_result,          # safely None — module must handle
            stealth=state.is_stealth_mode,
        )
        if auth_result:
            log.info(f"[SCAN] Auth findings : {auth_result.confirmed_count}")
            log.info(f"[SCAN] Attack chains : {len(auth_result.chain_opportunities)}")
            report.findings_by_module["broken_auth_idor"] = auth_result.confirmed_count

            state = _run_step(
                "AI Escalation (Auth/IDOR)",
                state,
                check_and_escalate,
                state=state,
                findings=_safe_findings(auth_result),
            )

    # AI Decision 2: Post-Scan — BUG 3 FIX (kwargs)
    state = _run_step(
        "AI Decision (Post-Scan)",
        state,
        ai_decision,
        state=state,
        phase=AnalysisPhase.POST_SCAN,
        tech_result=tech_dict,
        available_modules=["nuclei", "cve_lookup", "screenshot"],
    )

    # AI Final Triage — BUG 3 FIX (kwargs)
    state = _run_step(
        "AI Triage",
        state,
        ai_triage,
        state=state,
        tech_result=tech_dict,
    )

    # ── Populate final report ─────────────────────────────────────────────
    report.ai_tokens = getattr(state, "total_tokens", 0)
    report.ai_latency_ms = getattr(state, "total_latency_ms", 0.0)
    report.escalation_count = len(getattr(state, "escalations", []))

    triage = getattr(state, "triage", None)
    if triage:
        report.overall_risk = getattr(triage, "overall_risk", "unknown")
        report.writeup_count = len(getattr(triage, "writeups", []))

    return report


# ── CLI commands ──────────────────────────────────────────────────────────────


@app.command()
def scan(
    target: Annotated[
        Optional[str],
        typer.Option("--target", "-t", help="Single target domain (e.g. example.com)"),
    ] = None,
    targets_file: Annotated[
        Path,
        typer.Option("--file", "-f", help="Path to targets file (default: config/targets.txt)"),
    ] = Path(TARGETS_FILE),
    check_only: Annotated[
        bool,
        typer.Option("--check-only", help="Only run tool checks, do not scan"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug-level output"),
    ] = False,
) -> None:
    """Run a full VAPT scan against one or more targets."""
    print_banner()

    if verbose:
        log.setLevel("DEBUG")

    # ── BUG 8 FIX: Register signal handlers inside the command, not at module level
    # Module-level registration fires on import, breaking test isolation and any
    # tool that imports this module without intending to run the CLI.
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Bootstrap
    try:
        missing_tools = _bootstrap()
    except PhantomError as exc:
        log.error(str(exc))
        raise typer.Exit(1)

    if check_only:
        log.info("[PHANTOM] --check-only complete. Exiting.")
        raise typer.Exit(0)

    # Resolve target list
    targets: list[str] = []
    if target:
        targets = [target.strip()]
        log.info(f"[PHANTOM] Single target: {target}")
    else:
        try:
            targets = load_targets(str(targets_file))
            log.info(f"[PHANTOM] Loaded {len(targets)} target(s) from {targets_file}")
        except (FileNotFoundError, ValueError) as exc:
            log.error(str(exc))
            raise typer.Exit(1)

    # Validate all targets before entering pipeline
    validated: list[str] = []
    for t in targets:
        try:
            validated.append(validate_target(t))
        except ValueError as exc:
            log.error(f"[PHANTOM] Skipping invalid target: {exc}")
    targets = validated

    if not targets:
        log.error("[PHANTOM] No valid targets to scan.")
        raise typer.Exit(1)

    # ── Execute pipeline per target ───────────────────────────────────────
    section("Scan Pipeline")
    reports: list[ScanReport] = []
    failed: list[str] = []

    for t in targets:
        if _shutdown_requested:
            log.warning("[PHANTOM] Shutdown requested — stopping target loop.")
            break

        log.info(f"[PHANTOM] ── Target → {t}")
        try:
            report = _run_pipeline(t, missing_tools)
            reports.append(report)
            _print_report(report)
        except Exception as exc:  # noqa: BLE001
            log.error(f"[PHANTOM] Pipeline completely failed for {t}: {exc}", exc_info=True)
            failed.append(t)

    # ── Summary ───────────────────────────────────────────────────────────
    section("Summary")
    log.info(f"  Targets scanned  : {len(reports)}")
    log.info(f"  Targets failed   : {len(failed)}")
    total = sum(r.total_findings for r in reports)
    log.info(f"  Total findings   : {total}")

    if failed:
        log.warning(f"  Failed targets   : {', '.join(failed)}")

    # ── BUG 5 FIX: Three-tier exit codes ──────────────────────────────────
    # v2.0 only had exit 0 or 2, meaning partial failure silently exited 0.
    # Exit 0 = all targets completed successfully
    # Exit 1 = partial failure (some targets failed, some succeeded)
    # Exit 2 = total failure (all targets failed / nothing scanned)
    if failed and not reports:
        raise typer.Exit(2)
    if failed:
        raise typer.Exit(1)
    raise typer.Exit(0)


@app.command()
def version() -> None:
    """Show PHANTOM version."""
    typer.echo("PHANTOM v2.1.0 — VAPT Automator")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()