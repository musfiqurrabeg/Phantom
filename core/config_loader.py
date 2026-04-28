import os
from config.settings import ( 
    LOGS_DIR, OUTPUT_DIR, SCREENSHOT_DIR, 
    REPORT_HTML, REPORT_PDF, WORDLIST_DIR
)

REQUIRED_DIRS = [
    LOGS_DIR, 
    OUTPUT_DIR, 
    SCREENSHOT_DIR, 
    REPORT_HTML, 
    REPORT_PDF, 
    WORDLIST_DIR 
]

def init_dirs():
    """Create all required directories if they don't exist."""
    for directory in REQUIRED_DIRS:
        os.makedirs(directory, exist_ok=True)

def load_targets(target_file: str) -> list[str]:
    """Read target from targets.txt - one domain per line."""
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Target file not found: {target_file}")
    with open(target_file, "r") as f: 
        targets: list[str] = []
        for line in f:
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            targets.append(candidate)
    if not targets:
        raise ValueError("targets.txt is empty. Add at least one domain.")
    
    return targets