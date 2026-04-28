# PHANTOM — Web App VAPT Automation Framework

> Bug Bounty Automator | Python 3.11+

Autonomous web application penetration testing framework.
Chains recon → scanning → exploitation → reporting into one pipeline.

## Setup

```bash
git clone https://github.com/musfiqurrabeg/PHANTOM.git
cd PHANTOM
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
# Single target
python3 main.py scan --target example.com

# From targets file
python3 main.py scan --file config/targets.txt

# Tool check only
python3 main.py scan --check-only
```

## Legal

Only scan targets you have explicit written permission to test.
