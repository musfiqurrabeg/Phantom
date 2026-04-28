# modules/port_scanner.py
from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from config.settings import OUTPUT_DIR
from core.logger import get_logger, section
from core.tool_checker import require_tools
from modules.host_probe import ProbeResult

log = get_logger()

OUTPUT_PATH = Path(OUTPUT_DIR) / "ports"

# All imprtant Ports 
WEB_PORTS = "21,22,23,25,53,80,81,443,445,8080,8081,8443,8888,3000,3306,5432,6379,9200,27017"

# Nmap timing template — T3 is default, T4 is aggressive but faster
NMAP_TIMING = "T4"

# Nmap scan flags — SV = service version, sC = default scripts
NMAP_FLAGS = ["-sV", "-sC", "--open"]

# DATA MODELS
@dataclass
class PortRecord:
    """Represents a single open port on a host."""
    port:     int
    protocol: str # tcp / udp
    state:    str # open / filtered
    service:  str # http, ssh, ftp, etc.
    version:  str # e.g. "Apache httpd 2.4.41"
    scripts:  dict[str, str] = field(default_factory=dict) # output

    def to_dict(self) -> dict:
        return {
            "port":     self.port,
            "protocol": self.protocol,
            "state":    self.state,
            "service":  self.service,
            "version":  self.version,
            "scripts":  self.scripts,
        }
    
@dataclass
class HostScanResult:
    """Port scan results for a single host."""
    hostname: str
    ip: str
    ports: list[PortRecord] = field(default_factory=list)

    @property
    def open_port_numbers(self) -> list[int]:
        return [p.port for p in self.ports if p.state == "open"]
    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "open_ports": self.open_port_numbers,
            "ports": [p.to_dict() for p in self.ports]
        }
    
@dataclass
class PortScanResult:
    """Aggregated port scan results for all hosts under a target."""
    target: str
    hosts:  list[HostScanResult] = field(default_factory=list)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_port_numbers) for h in self.hosts)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hosts_scanned": len(self.hosts),
            "total_open_ports": self.total_open_ports,
            "hosts": [h.to_dict() for h in self.hosts],
        }
    
# XML PARSER
def _extract_xml_payload(output: str) -> str:
    """Extracts XML payload from command output, tolerating leading/trailing noise."""
    if not output:
        return ""

    start = output.find("<?xml")
    if start == -1:
        start = output.find("<nmaprun")
    if start == -1:
        return ""

    end = output.rfind("</nmaprun>")
    if end == -1:
        return ""

    return output[start:end + len("</nmaprun>")]


def _parse_nmap_xml(xml_output: str) -> list[PortRecord]:
    """
    Parses Nmap XML output into PortRecord list.
    Nmap's XML is the most reliable output format — never parse plaintext.
    Returns empty list if XML is malformed or no ports found.
    """
    payload = _extract_xml_payload(xml_output)
    if not payload.strip():
        return []

    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        log.error(f"[Nmap] XML parse failed: {exc}")
        return []

    ports: list[PortRecord] = []

    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem   = port_elem.find("state")
            service_elem = port_elem.find("service")

            if state_elem is None:
                continue

            state = state_elem.get("state", "unknown")
            if state not in ("open", "filtered"):
                continue

            raw_port_id = port_elem.get("portid", "")
            try:
                port_id = int(raw_port_id)
            except (TypeError, ValueError):
                log.warning(f"[Nmap] Skipping invalid port ID '{raw_port_id}'")
                continue

            if not 1 <= port_id <= 65535:
                log.warning(f"[Nmap] Skipping out-of-range port ID '{port_id}'")
                continue

            protocol = port_elem.get("protocol", "tcp")
            service  = service_elem.get("name", "unknown")    if service_elem is not None else "unknown"
            version  = service_elem.get("product", "")        if service_elem is not None else ""
            extra    = service_elem.get("extrainfo", "")      if service_elem is not None else ""
            ver_str  = service_elem.get("version", "")        if service_elem is not None else ""

            full_version = " ".join(filter(None, [version, ver_str, extra])).strip()

            # Extract nmap script output
            scripts: dict[str, str] = {}
            for script in port_elem.findall("script"):
                script_id     = script.get("id", "")
                script_output = script.get("output", "")
                if script_id:
                    scripts[script_id] = script_output

            ports.append(PortRecord(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service,
                version=full_version,
                scripts=scripts
            ))

    return ports

# NMAP RUNNER
def _run_nmap(ip: str, hostname: str) -> list[PortRecord]:
    """
    Runs Nmap against a single IP with XML output piped to stdout.
    Uses -oX - to stream XML directly — no temp files needed.
    """
    log.info(f"[Nmap] Scanning {hostname} ({ip})")

    cmd = [
        "nmap",
        *NMAP_FLAGS,
        f"-{NMAP_TIMING}",
        "-p", WEB_PORTS,
        "-oX", "-",          # XML output to stdout
        "--host-timeout", "60s",
        ip,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        log.warning(f"[Nmap] Timed out scanning {hostname}")
        return []
    except FileNotFoundError:
        log.error("[Nmap] Binary not found")
        return []

    if result.returncode not in (0, 1):
        # Nmap returns 1 when no hosts are up — not a real error
        log.error(f"[Nmap] Unexpected exit code {result.returncode} for {hostname}")
        log.error(f"[Nmap] stderr: {result.stderr.strip()[:200]}")
        return []

    if result.returncode == 1:
        stderr_text = result.stderr.strip()
        if stderr_text:
            log.warning(f"[Nmap] Exit code 1 on {hostname}: {stderr_text[:200]}")
        if not _extract_xml_payload(result.stdout).strip():
            log.warning(
                f"[Nmap] No XML payload returned for {hostname}; scan likely failed or host is down"
            )
            return []

    ports = _parse_nmap_xml(result.stdout)
    log.info(f"[Nmap] {hostname} → {len(ports)} open port(s)")

    for p in ports:
        log.info(f"  ↳ {p.port}/{p.protocol:<5} {p.service:<12} {p.version}")

    return ports


# SAVE RESULTS
def _save_results(result: PortScanResult) -> Path:
    """Saves PortScanResult to output/ports/<target>.json"""
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", result.target).strip("._-")
    if not safe_name:
        safe_name = "target"
    output_file = OUTPUT_PATH / f"{safe_name}_ports.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2)

    log.info(f"[Ports] Results saved → {output_file}")
    return output_file


# MAIN ENTRY POINT
def scan_ports(probe_result: ProbeResult) -> PortScanResult:
    """
    Takes ProbeResult from Step 7 (live hosts).
    Runs Nmap against each live host's IP.
    Returns PortScanResult with all open ports.
    """
    require_tools(["nmap"])
    section(f"Port Scanning → {probe_result.target}")

    if not probe_result.live_hosts:
        log.warning("[Ports] No live hosts to scan — skipping")
        return PortScanResult(target=probe_result.target)

    result = PortScanResult(target=probe_result.target)

    # Deduplicate by IP — no point scanning same IP twice
    seen_ips: set[str] = set()

    for host in probe_result.live_hosts:
        raw_ip = getattr(host, "ip_address", None) or getattr(host, "ip", None)
        host_name = str(getattr(host, "hostname", None) or getattr(host, "host", None) or "unknown-host")

        if not raw_ip:
            log.warning(f"[Nmap] Skipping host with missing IP ({host_name})")
            continue

        host_ip = str(raw_ip)

        if host_ip in seen_ips:
            log.info(f"[Nmap] Skipping duplicate IP {host_ip} ({host_name})")
            continue

        seen_ips.add(host_ip)
        ports = _run_nmap(ip=host_ip, hostname=host_name)

        result.hosts.append(HostScanResult(
            hostname=host_name,
            ip=host_ip,
            ports=ports,
        ))

    log.info(f"[Ports] Scan complete — {result.total_open_ports} open port(s) across {len(result.hosts)} host(s)")
    _save_results(result)
    return result