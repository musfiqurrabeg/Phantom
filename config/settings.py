# config/settings.py

import os


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable with safe defaults."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

# BASE PATHs
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "output", "screenshot")
REPORT_HTML = os.path.join(BASE_DIR, "reports", "html")
REPORT_PDF = os.path.join(BASE_DIR, "reports", "pdf")

# TARGET
TARGETS_FILE = os.path.join(BASE_DIR, "config", "targets.txt")

# API KEY
ANTHROPIC_API_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
SHODAN_API_KEY      = os.getenv("SHODAN_API_KEY", "")

# SCAN SETTINGS
HTTP_TIMEOUT = 50
MAX_THREAD = 20
RATE_LIMIT_DELAY = 0.5
MAX_RETRIES = 3
HTTP_VERIFY_SSL = _env_bool("HTTP_VERIFY_SSL", True)

# TOOLS PATHS
TOOLS = {
    "nmap": "nmap",
    "ffuf": "ffuf",
    "sqlmap": "sqlmap",
    "subfinder": "subfinder",
    "amass": "amass",
    "arjun": "arjun",
    "gowitness": "gowitness",
    "nuclei": "nuclei",
    "waybackurls": "waybackurls"
}

WORDLIST_DIR = os.path.join(BASE_DIR, "config", "wordlists")
DIR_WORDLIST = os.path.join(WORDLIST_DIR, "directories.txt")
PARAM_WORDLIST = os.path.join(WORDLIST_DIR, "parameters.txt")
SUBDOMAIN_WORDLIST = os.path.join(WORDLIST_DIR, "subdomains.txt")

REPORT_TITLE      = "VAPT Report"
REPORT_AUTHOR     = "VAPT"

SEVERITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Compatibility alias for code that expects MAX_THREADS
MAX_THREADS = MAX_THREAD

# Ensure required directories exist at startup
for _dir in (LOGS_DIR, OUTPUT_DIR, SCREENSHOT_DIR, REPORT_HTML, REPORT_PDF):
    os.makedirs(_dir, exist_ok=True)