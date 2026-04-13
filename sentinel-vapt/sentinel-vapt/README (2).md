# 🛡️ Sentinel VAPT Framework

> **Production-grade modular Vulnerability Assessment & Penetration Testing automation platform**
>
> Built for real security engagements | Safe-mode by default | CVSS v3 scoring | Consulting-grade reports

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=yellow)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/www-project-top-ten/)
[![Safe Mode](https://img.shields.io/badge/Mode-Safe%20Testing-brightgreen)](https://github.com/tanmoydaw26/sentinel-vapt-tool)

---

## 🎯 What Makes Sentinel Different

| ❌ Typical Tools | ✅ Sentinel |
|---|---|
| Nmap/Nikto wrappers | Custom detection logic written from scratch |
| Hardcoded severity labels | CVSS v3 scoring engine |
| Raw terminal output | Consulting-grade PDF / HTML / JSON reports |
| No correlation | Smart risk chaining engine |
| No SIEM export | Splunk JSONL ready |
| Monolithic design | Plugin architecture |

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/tanmoydaw26/sentinel-vapt-tool.git
cd sentinel-vapt-tool/sentinel-vapt/sentinel-vapt

# 2. Create virtual environment (required on Kali/Debian)
python3 -m venv sentinel-env
source sentinel-env/bin/activate        # Linux / Mac
# sentinel-env\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run your first scan
python scanner.py --target https://demo.owasp-juice.shop/#/search?q=test --full-scan
```

Reports appear in `output/` automatically.

---

## 🧪 Real Testing Environments

### Vulnerable Web Labs (Legal & Free)

| Target | What It Tests | Command |
|---|---|---|
| OWASP Juice Shop | OWASP Top 10 | `python scanner.py --target https://demo.owasp-juice.shop/#/search?q=test --full-scan` |
| Acunetix Vulnweb | SQLi, XSS, Headers | `python scanner.py --target http://testphp.vulnweb.com/search.php?test=test --full-scan` |
| DVWA via Docker | SQLi, Auth flaws | `python scanner.py --target http://localhost/vulnerabilities/sqli/?id=test --full-scan` |
| AltoroMutual | Web banking vulns | `python scanner.py --target http://demo.testfire.net/bank/login.aspx --full-scan` |

### Local Docker (100% Safe)

```bash
# Start DVWA locally
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Open new terminal, activate venv, then scan
source sentinel-env/bin/activate
python scanner.py --target http://localhost/vulnerabilities/sqli/?id=test --full-scan
```

### Network Testing

```bash
# Port scan only
python scanner.py --target scanme.nmap.org --ports 80,443,22,445

# Full scan on local network host
python scanner.py --target 192.168.1.1 --full-scan
```

---

## 📊 Report Output

```
output/
├── report.html          ← Dark consulting-grade report (open in browser)
├── report.pdf           ← Client-ready PDF
├── report.json          ← Structured raw data
└── splunk_events.jsonl  ← SIEM-ready Splunk logs
```

**Each report includes:**
- Executive summary (non-technical, client-ready)
- CVSS v3 score per vulnerability
- CWE + OWASP category mapping
- Proof-of-concept evidence
- Remediation steps
- Severity breakdown

**Open HTML report on Kali Linux:**

```bash
cp output/report.html /home/kali/Desktop/
firefox /home/kali/Desktop/report.html
```

---

## 🛠️ Detection Modules

```
Network Reconnaissance
├── Custom TCP Port Scanner     (no Nmap dependency)
├── Subdomain Enumeration
└── Directory Brute Forcing

Web Application Testing
├── SQL Injection               (basic + time-based)
├── Reflected XSS Detection
├── SSRF Parameter Detection
├── Open Redirect Validation
├── Security Header Audit       (CSP, HSTS, X-Frame-Options)
├── Sensitive Data Exposure     (keys, tokens, emails)
└── JWT Algorithm Weakness      (alg=none detection)

Authentication
└── Weak / Default Credential Checks

Enterprise
└── Active Directory Exposure   (LDAP, SMB, WinRM surface)
```

---

## 🎛️ CLI Usage

```bash
# Full scan (all modules, safe mode)
python scanner.py --target https://target.com/search?q=test --full-scan

# Port scan with custom ports
python scanner.py --target example.com --ports 80,443,8080,8443

# Specific target with params
python scanner.py --target http://testphp.vulnweb.com/search.php?test=test --full-scan

# Unsafe mode (⚠️ authorized targets only)
python scanner.py --target https://target.com --unsafe

# Custom output folder
python scanner.py --target https://target.com --full-scan --output /tmp/scan_results
```

---

## 🖥️ SOC Dashboard

```bash
# Start dashboard
python dashboard/app.py

# Open in browser
http://127.0.0.1:5000
```

Dark hacker-style interface showing scan progress, findings matrix, severity breakdown, and attack surface overview.

---

## 🔌 Plugin System

Add new vulnerability modules without touching the core engine:

```python
# modules/custom/my_check.py
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3

class MyCheckModule(BaseModule):
    name = 'my_check'
    category = 'custom'

    def run(self, context):
        findings = []
        # Your detection logic here
        score = CVSSv3.score(c='L', i='L', a='N')
        findings.append(Vulnerability(
            title='My Custom Finding',
            severity=CVSSv3.severity(score),
            cvss_score=score,
            cwe='CWE-XXX',
            owasp='A00:Custom',
            ...
        ))
        return findings
```

Register in `core/plugin_loader.py` and it auto-loads on next scan.

---

## 📁 Project Structure

```
sentinel-vapt/
├── scanner.py               ← CLI entrypoint
├── requirements.txt
├── core/
│   ├── engine.py            ← Scan orchestrator
│   ├── models.py            ← Data models
│   ├── cvss.py              ← CVSS v3 scoring engine
│   ├── analyzer.py          ← Correlation + FP reduction
│   ├── http_client.py       ← Rate-limited HTTP client
│   └── plugin_loader.py     ← Module registry
├── modules/
│   ├── network/             ← Port scan, subdomain enum
│   ├── web/                 ← SQLi, XSS, SSRF, headers...
│   ├── api/                 ← JWT checks
│   ├── auth/                ← Weak auth
│   └── ad/                  ← Active Directory
├── reporting/
│   └── report_generator.py  ← PDF / HTML / JSON engine
├── utils/
│   ├── helpers.py           ← Payloads, user agents
│   └── logger.py            ← Splunk JSONL logger
├── cli/
│   └── main.py
└── dashboard/
    ├── app.py               ← Flask dashboard
    └── templates/
        └── dashboard.html
```

---

## 📈 Expected Results

| Target | Expected Findings |
|---|---|
| DVWA | 3–5 (SQLi indicators, missing headers) |
| Juice Shop | 2–4 (header issues, param analysis) |
| Vulnweb | 4–6 (multiple endpoints) |
| Local network | Open ports + service exposure |

> **0 findings = normal** for hardened targets. Try URLs with `?param=value` query strings.

---

## 🐛 Troubleshooting

| Error | Fix |
|---|---|
| `externally-managed-environment` | `python3 -m venv sentinel-env && source sentinel-env/bin/activate` |
| Firefox root error on Kali | `cp output/report.html ~/Desktop/ && firefox ~/Desktop/report.html` |
| `ModuleNotFoundError` | `pip install -r requirements.txt` inside venv |
| No findings | Use targets with `?param=value` in URL |
| Dashboard port in use | Edit `dashboard/app.py` last line: `port=5001` |
| Scan too slow | Reduce port range: `--ports 80,443,8080` |

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security assessments only**.

- Only test systems you **own** or have **explicit written permission** to test
- Safe mode is enabled by default — no destructive actions
- The developer assumes no liability for unauthorized use
- Comply with all applicable local laws and regulations

---

## 📧 Contact

**Tanmoy Daw** — Cybersecurity Engineer | Penetration Tester  
📧 tanmoydawdaw@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/tanmoy-daw-a27a162aa/)  
💻 [GitHub](https://github.com/tanmoydaw26)

---

*Built for real VAPT engagements. Actively used in client security assessments.*
