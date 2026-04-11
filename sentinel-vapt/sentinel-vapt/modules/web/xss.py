from urllib.parse import urlencode, urlsplit, parse_qs, urlunsplit
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3
from utils.helpers import XSS_PAYLOADS

class XSSModule(BaseModule):
    name = 'xss'
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
            for payload in XSS_PAYLOADS:
                test_url = self.mutate(target, param, payload)
                try:
                    r = client.request('GET', test_url)
                    body = r.text
                    if payload in body:
                        score = CVSSv3.score(c='L', i='L', a='N')
                        findings.append(Vulnerability(
                            title='Reflected XSS',
                            description='Untrusted input is reflected in the response without proper encoding.',
                            severity=CVSSv3.severity(score),
                            cvss_score=score,
                            cwe='CWE-79',
                            owasp='A03:2021 Injection',
                            category='Injection',
                            affected_target=context['target'],
                            endpoint=parts.path or '/',
                            parameter=param,
                            poc=f'Payload reflected: {payload}',
                            remediation='Apply context-aware output encoding and sanitization.',
                            evidence=[Evidence(type='reflection', description='Payload reflected in body', data={'payload': payload})],
                            confidence=0.72,
                            tags=['xss', 'reflected-xss', 'owasp-a03']
                        ))
                        break
                except Exception:
                    continue
        return findings
