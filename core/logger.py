# core/logger.py

import logging
import os
from datetime import datetime
from config.settings import LOGS_DIR

# COLOR CODES TERMINAL
class Colors:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"

# COLORED FORMATTER
class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Colors.CYAN,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.MAGENTA,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, Colors.WHITE)
        time = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        level = f"{color}{record.levelname:<8}{Colors.RESET}"
        msg   = f"{color}{record.getMessage()}{Colors.RESET}"
        return f"{Colors.BOLD}[{time}]{Colors.RESET} {level} {msg}"


class PlainFormatter(logging.Formatter):
    def format(self, record):
        time  = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        return f"[{time}] [{record.levelname}] {record.getMessage()}"
    
def get_logger(name: str = "PHANTOM") -> logging.Logger:
    """
    Returns a logger that:
    - Prints colored output to terminal
    - Saves plain text to logs/phantom_YYYY-MM-DD.log
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Terminal Handler ─────────────────────────────────────
    terminal_handler = logging.StreamHandler()
    terminal_handler.setLevel(logging.INFO)
    terminal_handler.setFormatter(ColorFormatter())

    # ── File Handler ─────────────────────────────────────────
    os.makedirs(LOGS_DIR, exist_ok=True)
    log_filename = os.path.join(
        LOGS_DIR,
        f"phantom_{datetime.now().strftime('%Y-%m-%d')}.log"
    )
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(PlainFormatter())

    logger.addHandler(terminal_handler)
    logger.addHandler(file_handler)

    return logger

def print_banner():
    banner = f"""
{Colors.MAGENTA}{Colors.BOLD}
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{Colors.RESET}
{Colors.CYAN} VAPT Automation By @musfiqurrabeg{Colors.RESET}
{Colors.YELLOW} Bug Bounty Automator — macOS{Colors.RESET}
{Colors.WHITE} ─────────────────────────────────{Colors.RESET}
"""
    print(banner)


# ── SECTION PRINTER ──────────────────────────────────────────
def section(title: str):
    """Prints a clean section divider in terminal."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'─' * 50}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}  ▶  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'─' * 50}{Colors.RESET}\n")