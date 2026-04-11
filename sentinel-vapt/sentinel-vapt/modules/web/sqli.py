import time
from urllib.parse import urlencode, urlsplit, parse_qs, urlunsplit
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3
from utils.helpers import SQLI_PAYLOADS

class SQLInjectionModule(BaseModule):
    name = 'sqli'
    category = 'web'

    def mutate(self, url, param, payload):
        parts = urlsplit(url)
        qs = parse_qs(parts.query)
        qs[param] = payload
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(qs, doseq=True), parts.fragment))

    def run(self, context):
        target = context['target']
        client = context['client']
        findings = []
        parts = urlsplit(target)
        params = parse_qs(parts.query)
        for param in params:
            baseline_time = None
            try:
                t0 = time.time()
                client.request('GET', target)
                baseline_time = time.time() - t0
            except Exception:
                baseline_time = 0
            for payload in SQLI_PAYLOADS:
                test_url = self.mutate(target, param, payload)
                try:
                    t1 = time.time()
                    r = client.request('GET', test_url)
                    delta = time.time() - t1
                    body = r.text.lower()[:2000]
                    errors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'odbc', 'database error']
                    if any(e in body for e in errors) or ('sleep' in payload.lower() and baseline_time and delta > baseline_time + 4):
                        score = CVSSv3.score(c='H', i='H', a='L')
                        findings.append(Vulnerability(
                            title='SQL Injection',
                            description='Input appears to influence backend SQL processing.',
                            severity=CVSSv3.severity(score),
                            cvss_score=score,
                            cwe='CWE-89',
                            owasp='A03:2021 Injection',
                            category='Injection',
                            affected_target=context['target'],
                            endpoint=parts.path or '/',
                            parameter=param,
                            poc=f'Injected payload {payload!r} into parameter {param}.',
                            remediation='Use parameterized queries, ORM-safe patterns, and strict input validation.',
                            evidence=[Evidence(type='response', description='Potential SQLi indicators', data={'payload': payload, 'status': getattr(r, 'status_code', None), 'time_delta': round(delta, 2)})],
                            confidence=0.78 if 'sleep' not in payload.lower() else 0.85,
                            tags=['sqli', 'database', 'owasp-a03']
                        ))
                        break
                except Exception:
                    continue
        return findings
