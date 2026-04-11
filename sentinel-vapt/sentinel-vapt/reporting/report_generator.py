import json
import os
from collections import Counter
from jinja2 import Template
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel VAPT Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0f14;--surface:#0f1720;--surface2:#131d28;--card:#101923;--text:#e6edf3;--muted:#8b9fb3;--green:#2bd576;--red:#ff5d73;--amber:#ffbd59;--blue:#4da3ff;--border:#1f2b38;--purple:#8f7cff}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#091019,#0b1117 30%,#0b1014);color:var(--text);font-family:Inter,sans-serif}header{padding:40px 48px;border-bottom:1px solid var(--border);background:radial-gradient(circle at top right, rgba(43,213,118,.12), transparent 25%)}.brand{display:flex;align-items:center;gap:14px}.logo{width:40px;height:40px;border:1px solid var(--green);border-radius:12px;display:grid;place-items:center;color:var(--green);font-family:'JetBrains Mono',monospace;font-weight:700;box-shadow:0 0 18px rgba(43,213,118,.16)}h1,h2,h3{margin:0 0 12px}.muted{color:var(--muted)}.wrap{padding:32px 48px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin:24px 0}.card{background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:18px;padding:22px;box-shadow:0 8px 30px rgba(0,0,0,.22)}.kpi{font-size:30px;font-weight:800}.tag{display:inline-block;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700}.critical{background:rgba(255,93,115,.12);color:var(--red)}.high{background:rgba(255,189,89,.12);color:var(--amber)}.medium{background:rgba(77,163,255,.12);color:var(--blue)}.low{background:rgba(43,213,118,.12);color:var(--green)}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{padding:14px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left}th{color:#a8bac8;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.mono{font-family:'JetBrains Mono',monospace}.finding{margin:18px 0;padding:22px;border:1px solid var(--border);border-radius:18px;background:linear-gradient(180deg,#0e151e,#0d141c)}.cols{display:grid;grid-template-columns:2fr 1fr;gap:18px}.pill{display:inline-block;padding:4px 8px;border:1px solid var(--border);border-radius:999px;color:var(--muted);font-size:12px;margin-right:8px;margin-top:8px}.footer{padding:20px 48px;color:var(--muted);border-top:1px solid var(--border)}
@media(max-width:900px){.grid,.cols{grid-template-columns:1fr}.wrap,header,.footer{padding:22px}}
</style>
</head>
<body>
<header>
  <div class="brand"><div class="logo">S</div><div><h1>Sentinel VAPT Assessment Report</h1><div class="muted">Premium consulting-style client deliverable</div></div></div>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="muted">Target</div><div class="kpi mono">{{ target }}</div></div>
    <div class="card"><div class="muted">Total Findings</div><div class="kpi">{{ total }}</div></div>
    <div class="card"><div class="muted">Risk Index</div><div class="kpi">{{ risk_index }}</div></div>
    <div class="card"><div class="muted">Top Severity</div><div class="kpi">{{ top_severity }}</div></div>
  </div>

  <div class="cols">
    <div class="card">
      <h2>Executive Summary</h2>
      <p class="muted">This assessment identified {{ total }} validated findings across exposed services, web logic, API controls, and authentication pathways. The highest business risks arise from issues that can lead to unauthorized access, data exposure, or trust abuse in user workflows.</p>
      <p class="muted">The scan operated in safe mode, meaning validation focused on low-impact proof rather than intrusive exploitation. Findings are prioritized using CVSS v3-style scoring, confidence, and correlation logic.</p>
    </div>
    <div class="card">
      <h2>Severity Mix</h2>
      {% for sev,count in severities.items() %}
      <div style="display:flex;justify-content:space-between;padding:8px 0"><span class="tag {{ sev|lower }}">{{ sev }}</span><strong>{{ count }}</strong></div>
      {% endfor %}
    </div>
  </div>

  <div class="card" style="margin-top:18px">
    <h2>Technical Findings</h2>
    {% for f in findings %}
      <div class="finding">
        <div style="display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center">
          <h3>{{ f.title }}</h3>
          <div>
            <span class="tag {{ f.severity|lower }}">{{ f.severity }}</span>
            <span class="pill">CVSS {{ f.cvss_score }}</span>
            <span class="pill">{{ f.cwe }}</span>
            <span class="pill">{{ f.owasp }}</span>
          </div>
        </div>
        <p>{{ f.description }}</p>
        <table>
          <tr><th>Target</th><td class="mono">{{ f.affected_target }}</td></tr>
          <tr><th>Endpoint</th><td class="mono">{{ f.endpoint }}</td></tr>
          <tr><th>Parameter</th><td class="mono">{{ f.parameter }}</td></tr>
          <tr><th>PoC</th><td class="mono">{{ f.poc }}</td></tr>
          <tr><th>Remediation</th><td>{{ f.remediation }}</td></tr>
          <tr><th>Confidence</th><td>{{ f.confidence }}</td></tr>
          <tr><th>Evidence</th><td class="mono">{{ f.evidence }}</td></tr>
        </table>
      </div>
    {% endfor %}
  </div>
</div>
<div class="footer">Generated by Sentinel VAPT Framework · HTML / JSON / PDF output suite</div>
</body>
</html>
"""

class ReportGenerator:
    def __init__(self, result):
        self.result = result

    def _severity_counter(self):
        c = Counter(f.severity for f in self.result.findings)
        ordered = {}
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if c.get(sev):
                ordered[sev] = c[sev]
        return ordered

    def generate_json(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.result.to_dict(), f, indent=2)

    def generate_html(self, path):
        severities = self._severity_counter()
        risk_index = round(sum(f.cvss_score for f in self.result.findings) / max(len(self.result.findings), 1), 1)
        top_sev = next(iter(severities.keys()), 'Info')
        html = Template(HTML_TEMPLATE).render(
            target=self.result.target,
            total=len(self.result.findings),
            findings=[f.to_dict() for f in self.result.findings],
            severities=severities,
            risk_index=risk_index,
            top_severity=top_sev
        )
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_pdf(self, path):
        doc = SimpleDocTemplate(path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph('Sentinel VAPT Assessment Report', styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f'Target: {self.result.target}', styles['Normal']))
        story.append(Paragraph(f'Total Findings: {len(self.result.findings)}', styles['Normal']))
        story.append(Spacer(1, 12))
        sev_table = [['Title', 'Severity', 'CVSS', 'CWE', 'OWASP']]
        for f in self.result.findings:
            sev_table.append([f.title, f.severity, str(f.cvss_score), f.cwe, f.owasp])
        table = Table(sev_table, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.black),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
        ]))
        story.append(table)
        story.append(Spacer(1, 18))
        for f in self.result.findings:
            story.append(Paragraph(f'<b>{f.title}</b> ({f.severity}, CVSS {f.cvss_score})', styles['Heading3']))
            story.append(Paragraph(f.description, styles['BodyText']))
            story.append(Paragraph(f'PoC: {f.poc}', styles['Code']))
            story.append(Paragraph(f'Remediation: {f.remediation}', styles['BodyText']))
            story.append(Spacer(1, 10))
        doc.build(story)
