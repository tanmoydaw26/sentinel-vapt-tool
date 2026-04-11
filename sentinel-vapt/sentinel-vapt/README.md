# Sentinel VAPT Framework

Sentinel is a modular VAPT automation platform designed for portfolio-grade and practical safe-mode security assessments.

## Architecture

### Core layers
- `core/` — orchestration engine, CVSS v3 scorer, HTTP client, plugin loader, smart analyzer
- `modules/` — attack-surface and vulnerability checks, each in its own module
- `reporting/` — JSON, HTML, PDF premium reporting engine
- `utils/` — helpers, rate-limited request logic, randomized headers, Splunk log exporter
- `cli/` — command-line entrypoint
- `dashboard/` — Flask-based dark security console

### Unique capabilities
- Dynamic CVSS v3 scoring engine
- Correlation engine to raise risk when weaknesses combine
- False-positive reduction via confidence filtering
- OWASP and CWE tagging
- Splunk-friendly JSONL event export
- Safe-mode exploitation validation only
- Plugin-ready architecture for new modules
- AD exposure module for Windows/enterprise attack surface visibility

## Included detection modules
- Custom TCP port scanning
- Subdomain enumeration
- Directory brute forcing
- Security header audit
- SQL injection (basic plus time-based heuristics)
- XSS reflection detection
- SSRF heuristic detection
- Open redirect detection
- Sensitive data exposure checks
- JWT weakness checks
- Weak authentication/default credential checks
- Active Directory exposure checks

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py --target https://example.com/search?q=test --full-scan
python scanner.py --target example.com --ports 80,443,8080
python scanner.py --target https://target.tld/reset?next=/home --full-scan
```

## Dashboard

```bash
python dashboard/app.py
```

## Example outputs
- `output/report.json`
- `output/report.html`
- `output/report.pdf`
- `output/splunk_events.jsonl`

## Safety model
Sentinel defaults to safe mode. It validates issues with lightweight checks and avoids intrusive exploitation paths.
