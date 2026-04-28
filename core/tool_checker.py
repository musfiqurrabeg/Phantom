# core/tool_checker.py
import shutil
import subprocess
from core.logger import get_logger, section
from config.settings import TOOLS

log = get_logger()

INSTALL_GUIDE = {
    "nmap": "brew install nmap",
    "ffuf": "brew install ffuf",
    "sqlmap": "pip install sqlmap",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "brew install amass",
    "httpx": "pip install httpx",
    "arjun": "pip install arjun",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
}

def check_tool(tool_name: str, tool_command: str | None = None) -> bool:
    """
    Returns True if tool is found in system PATH.
    Returns False if missing.
    """

    command = tool_command or tool_name
    path = shutil.which(command)
    if path:
        log.info(f"[✔] {tool_name:<15} found at {path}")
        return True
    else:
        install_cmd = INSTALL_GUIDE.get(tool_name, "Not available via brew/go/pip")
        log.error(f"[✘] {tool_name:<15} NOT FOUND ({command})")
        log.warning(f"Install: {install_cmd}")
        return False
    
def check_all_tools() -> dict:
    """
    Checks every tool in settings.TOOLS.
    Returns a dict: { tool_name: True/False }
    """
    section("Tool dependency check")
    
    results = {}
    missing = []

    for tool_name, tool_command in TOOLS.items():
        found = check_tool(tool_name, tool_command)
        results[tool_name] = found
        if not found:
            missing.append(tool_name)
    
    # Summary
    print()
    total = len(results)
    passed = sum(results.values())
    failed = total - passed
    log.info(f"Tools found: {passed}/{total}")

    if missing:
        log.warning(f"Tools missing: {failed}/{total}")
        log.warning(f"Missing: {', '.join(missing)}")
    else:
        log.info("All tools ready. PHANTOM is fully armed.")

    return results

def get_version(tool_name: str) -> str:
    """
    Tries to get the version string of a tool.
    Returns version string or 'unknown'.
    """
    version_flags = {
        "nmap": ["nmap", "--version"],
        "ffuf": ["ffuf", "-V"],
        "sqlmap": ["sqlmap", "--version"],
        "subfinder": ["subfinder", "-version"],
        "amass": ["amass", "-version"],
        "nuclei": ["nuclei", "-version"],
        "gowitness": ["gowitness", "version"],
        "waybackurls": ["waybackurls", "--help"],
    }
    cmd = version_flags.get(tool_name)
    if not cmd:
        return "unknown"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout.strip() or result.stderr.strip()
        # Return just the first line
        return output.split("\n")[0] if output else "unknown"
    except Exception:
        return "unknown"

# REQUIRE TOOLS
def require_tools(tool_list: list[str]) -> None:
    """
    Call this at the start of any module.
    If any required tool is missing → raises RuntimeError.
    Scan will NOT start with missing critical tools.
    """
    missing: list[str] = []
    for tool_name in tool_list:
        command = TOOLS.get(tool_name, tool_name)
        if not shutil.which(command):
            missing.append(tool_name)

    if missing:
        for t in missing:
            command = TOOLS.get(t, t)
            install_cmd = INSTALL_GUIDE.get(t, "unknown")
            log.error(f"Required tool missing: {t} ({command})")
            log.warning(f"Install with: {install_cmd}")
        raise RuntimeError(
            f"Cannot proceed. Missing tools: {', '.join(missing)}"
        )