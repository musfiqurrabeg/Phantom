from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from config.settings import HTTP_TIMEOUT, HTTP_VERIFY_SSL, MAX_THREAD, OUTPUT_DIR
from core.logger import get_logger, section
from modules.subdomain_enum import SubdomainResult


log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "hosts"

# Probe both HTTP and HTTPS for every host
PROBE_SCHEMES: tuple[str, ...] = ("https", "http")

# How many hosts to probe concurrently
CONCURRENCY_LIMIT = MAX_THREAD

@dataclass
class HostRecord:
    """Represents a single resolved, live host."""
    hostname: str
    ip_address: str
    scheme: str
    status_code: int
    content_length: int
    server_header: str
    redirect_url: str | None = None
    

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.hostname}"
    
    def to_dict(self) -> dict:
        return {
            "hostname":       self.hostname,
            "ip_address":     self.ip_address,
            "url":            self.url,
            "status_code":    self.status_code,
            "content_length": self.content_length,
            "server_header":  self.server_header,
            "redirect_url":   self.redirect_url,
        }
    
@dataclass
class ProbeResult:
    """Holds all live hosts discovered foor a target"""
    target: str
    live_hosts: list[HostRecord] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.live_hosts)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "live_count": self.count,
            "hosts": [h.to_dict() for h in self.live_hosts]
        }

# DNS RESOLUTION
def _resolve_dns(hostname: str) -> str | None:
    """
    Resolves hostname to IP address using system DNS.
    Returns IP string on success, None if unresolvable.
    Uses socket.getaddrinfo — stdlib, no external deps.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        # results is list of (family, type, proto, canonname, sockaddr)
        # sockaddr is (ip, port) for AF_INET
        return str(results[0][4][0])
    except (socket.gaierror, IndexError):
        return None


def _safe_content_length(headers: httpx.Headers) -> int:
    """Parse content-length safely; return 0 when header is missing or invalid."""
    raw = headers.get("content-length", "0")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0
    
# ASYNC HTTP PROBE
async def _probe_host(
        client: httpx.AsyncClient,
        hostname: str,
        ip_address: str
) -> HostRecord | None:
    """
    Probes hostname over HTTPS first, falls back to HTTP.
    Returns HostRecord if any scheme responds, None otherwise.
    Follows redirects, captures final status + headers.
    """
    for scheme in PROBE_SCHEMES:
        url = f"{scheme}://{hostname}"
        try:
            response = await client.get(url, follow_redirects=True)

            server_header = response.headers.get("server", "unknown")
            content_length = _safe_content_length(response.headers)

            # Capture redirect chain final URL if redirected
            redirect_url: str | None = None
            if response.history:
                redirect_url = str(response.url)

            return HostRecord(
                hostname=hostname,
                ip_address=ip_address,
                scheme=scheme,
                status_code=response.status_code,
                content_length=content_length,
                server_header=server_header,
                redirect_url=redirect_url,
            )

        except httpx.TimeoutException:
            log.warning(f"[Probe] Timeout → {url}")
        except httpx.ConnectError:
            pass  # Connection refused — try next scheme silently
        except httpx.TooManyRedirects:
            log.warning(f"[Probe] Too many redirects → {url}")
        except httpx.HTTPError as exc:
            log.warning(f"[Probe] HTTP error → {url}: {type(exc).__name__}")
        except Exception as exc:
            log.warning(f"[Probe] Unexpected error → {url}: {type(exc).__name__}")

    return None


# BATCH PROBER
async def _probe_all_hosts(resolved: dict[str, str]) -> list[HostRecord]:
    """
    Probes all resolved hosts concurrently using asyncio semaphore.
    Semaphore limits concurrent connections to CONCURRENCY_LIMIT.
    Returns list of live HostRecords.
    """
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    live_hosts: list[HostRecord] = []

    async def _bounded_probe(
        client: httpx.AsyncClient,
        hostname: str,
        ip_address: str,
    ) -> HostRecord | None:
        async with semaphore:
            return await _probe_host(client, hostname, ip_address)

    timeout = httpx.Timeout(connect=5.0, read=HTTP_TIMEOUT, write=5.0, pool=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=HTTP_VERIFY_SSL,
        follow_redirects=True,
    ) as client:
        tasks = [
            _bounded_probe(client, hostname, ip)
            for hostname, ip in resolved.items()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for record in results:
        if isinstance(record, BaseException):
            log.warning(f"[Probe] Worker task failed: {type(record).__name__}: {record}")
            continue
        if isinstance(record, HostRecord):
            live_hosts.append(record)

    return live_hosts

# SAVE RESULTS
def _save_results(result: ProbeResult) -> Path:
    """Saves ProbeResult to output/hosts/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name = result.target.replace(".", "_")
    output_file = OUTPUT_PATH / f"{safe_name}_hosts.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[Hosts] Results saved → {output_file}")
    return output_file

# MAIN ENTRY POINT
def probe_live_hosts(subdomain_result: SubdomainResult) -> ProbeResult:
    """
    1. Resolves each subdomain via DNS
    2. HTTP-probes all resolved hosts concurrently
    3. Returns only live hosts as ProbeResult
    """
    section(f"Live Host Detection → {subdomain_result.target}")

    all_hosts = subdomain_result.subdomains | {subdomain_result.target}

    if not all_hosts:
        log.warning("[Hosts] No subdomains to probe — skipping")
        return ProbeResult(target=subdomain_result.target)

    # DNS Resolution
    log.info(f"[DNS] Resolving {len(all_hosts)} hostnames...")
    resolved: dict[str, str] = {}

    for hostname in sorted(all_hosts):
        ip = _resolve_dns(hostname)
        if ip:
            resolved[hostname] = ip
            log.info(f"[DNS] ✔ {hostname:<40} → {ip}")
        else:
            log.warning(f"[DNS] ✘ {hostname} — unresolvable, skipping")

    log.info(f"[DNS] Resolved: {len(resolved)}/{len(all_hosts)}")

    if not resolved:
        log.warning("[Hosts] No hostnames resolved — aborting probe")
        return ProbeResult(target=subdomain_result.target)

    # HTTP Probing
    log.info(f"[Probe] Probing {len(resolved)} hosts (concurrency={CONCURRENCY_LIMIT})...")
    live_hosts = asyncio.run(_probe_all_hosts(resolved))

    # Summary
    result = ProbeResult(
        target=subdomain_result.target,
        live_hosts=sorted(live_hosts, key=lambda h: h.hostname),
    )

    log.info(f"[Hosts] Live hosts: {result.count}/{len(resolved)}")
    for host in result.live_hosts:
        log.info(f"  ↳ [{host.status_code}] {host.url:<45} IP={host.ip_address}  Server={host.server_header}")

    _save_results(result)
    return result