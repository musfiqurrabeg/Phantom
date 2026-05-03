# modules/xss_verifier.py
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs

from core.logger import get_logger
from core.sanitize import safe_filename
from config.settings import OUTPUT_DIR

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "xss"

# Playwright browser launch timeout in ms
BROWSER_LAUNCH_TIMEOUT_MS: int = 30_000

# Per-page navigation timeout in ms
PAGE_TIMEOUT_MS: int = 15_000

# How long to wait for dialog after page load in ms
DIALOG_WAIT_MS: int = 5_000

# Max concurrent browser pages — more than 4 causes memory pressure
MAX_BROWSER_PAGES: int = 4


# ── DATA MODELS ───────────────────────────────────────────────

@dataclass
class VerificationResult:
    """Execution verification result for a single XSS finding."""
    url:       str
    parameter: str
    payload:   str
    executed:  bool        # True = confirm() dialog fired in real browser
    dialog_message: str    # What the dialog said — proof
    screenshot_path: str | None = None

    def to_dict(self) -> dict:
        return {
            "url":            self.url,
            "parameter":      self.parameter,
            "payload":        self.payload,
            "executed":       self.executed,
            "dialog_message": self.dialog_message,
            "screenshot_path": self.screenshot_path,
        }


@dataclass
class VerifierReport:
    """Complete verification report for all findings."""
    target:   str
    verified: list[VerificationResult] = field(default_factory=list)

    @property
    def executed_count(self) -> int:
        return sum(1 for r in self.verified if r.executed)

    def to_dict(self) -> dict:
        return {
            "target":         self.target,
            "total_verified": len(self.verified),
            "executed":       self.executed_count,
            "results":        [r.to_dict() for r in self.verified],
        }


# ── URL BUILDER ───────────────────────────────────────────────

def _build_payload_url(
    url:       str,
    parameter: str,
    payload:   str,
) -> str:
    """
    Injects payload into parameter in the URL query string.
    Only handles GET — POST verification requires form submission
    which Playwright handles separately.
    """
    parsed      = urlparse(url)
    base_params = parse_qs(parsed.query, keep_blank_values=True)
    merged      = {k: v[0] if v else "" for k, v in base_params.items()}
    merged[parameter] = payload
    return parsed._replace(query=urlencode(merged)).geturl()


# ── SINGLE FINDING VERIFIER ───────────────────────────────────

async def _verify_finding(
    browser_context,  # playwright BrowserContext — typed as Any to avoid import at module level
    finding_url:   str,
    parameter:     str,
    payload:       str,
    method:        str,
    sem:           asyncio.Semaphore,
) -> VerificationResult:
    """
    Opens a real headless browser page with the payload injected.
    Listens for confirm() dialog — if it fires, finding is EXECUTED.
    Takes screenshot as evidence regardless of outcome.
    """
    result = VerificationResult(
        url=finding_url,
        parameter=parameter,
        payload=payload,
        executed=False,
        dialog_message="",
    )

    async with sem:
        page = await browser_context.new_page()
        dialog_fired  = asyncio.Event()
        dialog_text   = ""

        def _on_dialog(dialog) -> None:
            nonlocal dialog_text
            dialog_text = dialog.message
            dialog_fired.set()
            # Schedule dismiss — can't await inside sync callback
            asyncio.create_task(dialog.dismiss())

        page.on("dialog", _on_dialog)

        try:
            if method.upper() == "GET":
                nav_url = _build_payload_url(finding_url, parameter, payload)
                await page.goto(
                    nav_url,
                    timeout=PAGE_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
            else:
                # POST: navigate to base URL, then submit via evaluate
                await page.goto(
                    finding_url,
                    timeout=PAGE_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                # Inject payload via form submission through page JS.
                # Pass data as arguments to avoid JS string/template injection issues.
                await page.evaluate(
                    """
                    ({ findingUrl, parameter, payload }) => {
                        const form = document.querySelector("form") || document.createElement("form");
                        form.method = "POST";
                        form.action = findingUrl;

                        const input = document.createElement("input");
                        input.type = "hidden";
                        input.name = parameter;
                        input.value = payload;
                        form.appendChild(input);

                        if (!form.isConnected) {
                            document.body.appendChild(form);
                        }

                        form.submit();
                    }
                    """,
                    {
                        "findingUrl": finding_url,
                        "parameter": parameter,
                        "payload": payload,
                    },
                )

            # Wait for dialog with timeout
            try:
                await asyncio.wait_for(
                    asyncio.shield(dialog_fired.wait()),
                    timeout=DIALOG_WAIT_MS / 1000,
                )
                result.executed       = True
                result.dialog_message = dialog_text
                log.warning(
                    f"[Verifier] ★ EXECUTED — {finding_url} "
                    f"?{parameter}\n"
                    f"           Dialog: '{dialog_text}'"
                )
            except asyncio.TimeoutError:
                result.executed = False

            # Screenshot — saved whether executed or not
            screenshot_dir  = OUTPUT_PATH / "screenshots"
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            safe_param      = parameter.replace("/", "_")[:20]
            safe_host       = urlparse(finding_url).netloc.replace(".", "_")
            screenshot_file = screenshot_dir / f"{safe_host}_{safe_param}.png"

            await page.screenshot(path=str(screenshot_file), full_page=False)
            result.screenshot_path = str(screenshot_file)

        except Exception as exc:  # noqa: BLE001 — broad catch intentional for browser errors
            # Playwright raises generic exceptions for navigation failures
            # We log and continue — one bad page never kills the verifier
            log.warning(f"[Verifier] Page error on {finding_url}: {type(exc).__name__}: {exc}")

        finally:
            await page.close()

    return result


# ── ASYNC ORCHESTRATOR ────────────────────────────────────────

async def _run_verification(
    findings: list[dict],
    target:   str,
) -> VerifierReport:
    """
    Async core — launches Playwright Chromium, verifies all findings concurrently.
    findings: list of XSSFinding.to_dict() dicts from the HTTP scanner.
    """
    # Import here — keeps playwright optional (won't crash if not installed)
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright not installed. Run: pip install playwright && playwright install chromium"
        ) from exc

    report = VerifierReport(target=target)
    sem    = asyncio.Semaphore(MAX_BROWSER_PAGES)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            timeout=BROWSER_LAUNCH_TIMEOUT_MS,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-web-security",     # Allows cross-origin payloads to fire
                "--disable-features=IsolateOrigins,site-per-process",
            ],
        )

        # Single context — shared cookies/state across pages
        context = await browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
            user_agent="Mozilla/5.0 (compatible; PHANTOM-Verifier/1.0)",
        )

        tasks = [
            _verify_finding(
                browser_context=context,
                finding_url=f["url"],
                parameter=f["parameter"],
                payload=f["payload"],
                method=f.get("method", "GET"),
                sem=sem,
            )
            for f in findings
            if f.get("is_confirmed", False)  # Only verify HTTP-confirmed findings
        ]

        if not tasks:
            log.warning("[Verifier] No confirmed findings to verify")
            await context.close()
            await browser.close()
            return report

        log.info(f"[Verifier] Verifying {len(tasks)} confirmed finding(s) in real browser")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for verification in results:
            if isinstance(verification, BaseException):
                log.warning(
                    f"[Verifier] Worker failed: "
                    f"{type(verification).__name__}: {verification}"
                )
                continue
            report.verified.append(verification)

        await context.close()
        await browser.close()

    return report


# ── SAVE RESULTS ──────────────────────────────────────────────

def _save_report(report: VerifierReport) -> Path:
    """Saves VerifierReport to output/xss/<target>_verified.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name   = safe_filename(report.target)
    output_file = OUTPUT_PATH / f"{safe_name}_xss_verified.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    log.info(f"[Verifier] Report saved → {output_file}")
    return output_file


# ── MAIN ENTRY POINT ──────────────────────────────────────────

def verify_xss_findings(
    xss_scan_result_dict: dict,
    target: str,
) -> VerifierReport:
    """
    Takes the dict output of XSSScanResult.to_dict() from the HTTP scanner.
    Runs Playwright verification on all is_confirmed=True findings.
    Returns VerifierReport with EXECUTED=True only when browser confirms dialog.

    This is the only real XSS confirmation. HTTP reflection ≠ execution.
    """
    findings = xss_scan_result_dict.get("findings", [])
    confirmed = [f for f in findings if f.get("is_confirmed", False)]

    if not confirmed:
        log.info("[Verifier] No HTTP-confirmed findings to verify — skipping browser")
        return VerifierReport(target=target)

    log.info(f"[Verifier] Starting Playwright verification — {len(confirmed)} finding(s)")

    report = asyncio.run(_run_verification(confirmed, target))

    log.info(f"[Verifier] Verified: {len(report.verified)}")
    log.info(f"[Verifier] EXECUTED: {report.executed_count}")

    if report.executed_count:
        log.warning(f"[Verifier] ★ {report.executed_count} finding(s) CONFIRMED EXECUTED in browser")

    _save_report(report)
    return report