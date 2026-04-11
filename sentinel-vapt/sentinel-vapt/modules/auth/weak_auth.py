from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3

class WeakAuthModule(BaseModule):
    name = 'weak_auth'
    category = 'auth'

    def run(self, context):
        findings = []
        login_url = context['target'].rstrip('/') + '/login'
        client = context['client']
        weak_pairs = [('admin', 'admin'), ('test', 'test'), ('guest', 'guest')]
        for username, password in weak_pairs:
            try:
                r = client.request('POST', login_url, data={'username': username, 'password': password})
                if r.status_code in [200, 302] and 'invalid' not in r.text.lower() and 'incorrect' not in r.text.lower():
                    score = CVSSv3.score(c='H', i='H', a='L')
                    findings.append(Vulnerability(
                        title='Weak Authentication',
                        description='Application may accept default or weak credentials.',
                        severity=CVSSv3.severity(score),
                        cvss_score=score,
                        cwe='CWE-1391',
                        owasp='A07:2021 Identification and Authentication Failures',
                        category='Authentication',
                        affected_target=context['target'],
                        endpoint='/login',
                        parameter='username/password',
                        poc=f'Safe-mode credential check succeeded or behaved unusually with {username}/{password}.',
                        remediation='Disable default credentials, enforce MFA, rate limits, and strong password policy.',
                        evidence=[Evidence(type='auth-response', description='Potential weak credential acceptance', data={'username': username, 'status_code': r.status_code})],
                        confidence=0.62,
                        tags=['auth', 'credentials', 'owasp-a07']
                    ))
                    break
            except Exception:
                continue
        return findings
