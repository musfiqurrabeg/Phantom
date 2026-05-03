<div align="center">

# 🥷 PHANTOM
**Next-Generation Web App VAPT Automation Framework**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Mode](https://img.shields.io/badge/Mode-Bug_Bounty-red.svg)]()
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey.svg)]()

*Automate the boring. Hunt the critical.*
</div>

---

**PHANTOM** is an autonomous, AI-driven penetration testing and bug bounty framework. It intelligently chains reconnaissance, vulnerability scanning, and exploitation into a single, cohesive pipeline. Powered by an integrated AI brain, PHANTOM dynamically adapts its attack surface mapping, drops stealth mode payloads, and automatically escalates critical findings.

## 🔥 Key Features

* **🧠 Autonomous AI Brain**: Uses an LLM to actively monitor scan state, triage findings, deduplicate vulnerabilities, and dynamically recommend runtime execution paths.
* **🌐 Complete Reconnaissance**: Automated subdomain enumeration, live host probing, port scanning, technology fingerprinting, and Wayback Machine URL harvesting.
* **⚔️ Deep Vulnerability Scanning**:
  * **XSS Hunter**: Context-aware reflected & DOM-based XSS scanning with automated Playwright browser execution verification.
  * **SQLi Engine**: Advanced pre-filter, error, boolean, and time-based SQL injection detection with seamless `sqlmap` exploitation hooks.
  * **SSRF & Open Redirect**: Automated out-of-band (OOB) interactions and canary payload injections.
  * **Broken Auth & IDOR**: Detection of horizontal/vertical IDORs, JWT `alg:none` vulnerabilities, mass assignment, and race conditions.
  * **JS & Param Analysis**: Extracts API secrets and hidden parameters directly from minified JavaScript bundles.
* **⚡ Concurrency & Resilience**: Built heavily on `asyncio`. A single target failure will never crash the pipeline, and intelligent cross-module deduplication prevents alert fatigue.
* **🛡️ Defensive Posturing**: Built-in sanitization to protect the operator against path traversal, command injection, and SSRF attacks from malicious targets.

## 🛠️ Required Tools

PHANTOM seamlessly orchestrates the industry's best open-source security tools. Ensure these are installed and accessible in your system's `$PATH`:

* `nmap`
* `ffuf`
* `subfinder`
* `amass`
* `gowitness`
* `nuclei`
* `waybackurls`
* `sqlmap` *(Managed automatically in the Python `venv`)*
* `arjun` *(Managed automatically in the Python `venv`)*

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/musfiqurrabeg/Phantom.git
cd Phantom

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install core dependencies
pip install -r requirements.txt

# Install Playwright browsers (for XSS verification & Screenshotting)
playwright install chromium
```

## 🎯 Usage

PHANTOM features a clean, beautifully formatted CLI experience built with Typer and Rich.

```bash
# Scan a single target domain
python3 main2.py scan --target example.com

# Scan a batch of domains from a file
python3 main2.py scan --file config/targets.txt

# Verify your environment and tool installations without scanning
python3 main2.py scan --check-only

# Run in Verbose/Debug mode
python3 main2.py scan --target example.com -v
```

> **Note**: `main2.py` is the state-of-the-art orchestration layer leveraging the AI Brain. The legacy `main.py` is preserved for purely linear, non-AI operational flows.

## ⚙️ Configuration

Global settings, timeouts, and OOB listener configurations are managed in `config/settings.py`.

To utilize the AI Brain, ensure you set your OpenRouter API key before executing the script:

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

## ⚠️ Legal Disclaimer

**PHANTOM is created strictly for educational purposes, authorized penetration testing, and legitimate bug bounty hunting.** 
You may only use this framework against targets you have explicit, written permission to test. The authors and contributors are not responsible for any misuse, damage, or legal consequences caused by this tool.
