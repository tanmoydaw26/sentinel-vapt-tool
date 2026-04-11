from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3

class HeaderCheck(BaseModule):
    name = 'headers_check'
    category = 'web'

    def run(self, context):
        client = context['client']
        findings = []
        try:
            r = client.request('GET', context['target'])
            missing = []
            required = [
                'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
                'Referrer-Policy', 'Strict-Transport-Security'
            ]
            for h in required:
                if h not in r.headers:
                    missing.append(h)
            if missing:
                score = CVSSv3.score(c='L', i='L', a='N')
                findings.append(Vulnerability(
                    title='Missing Security Headers',
                    description='Important browser-enforced security headers are absent.',
                    severity=CVSSv3.severity(score),
                    cvss_score=score,
                    cwe='CWE-693',
                    owasp='A05:2021 Security Misconfiguration',
                    category='Security Misconfiguration',
                    affected_target=context['target'],
                    endpoint=context['target'],
                    poc='Observe missing headers in HTTP response.',
                    remediation='Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.',
                    evidence=[Evidence(type='headers', description='Missing headers', data={'missing': missing})],
                    tags=['owasp', 'headers', 'misconfiguration']
                ))
        except Exception:
            pass
        return findings
