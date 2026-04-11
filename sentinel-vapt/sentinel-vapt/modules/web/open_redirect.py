from urllib.parse import urlencode, urlsplit, parse_qs, urlunsplit
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3
from utils.helpers import REDIRECT_PAYLOADS

class OpenRedirectModule(BaseModule):
    name = 'open_redirect'
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
        params = parse_qs(urlsplit(target).query)
        redirect_keys = ['next', 'url', 'redirect', 'return', 'returnTo']
        for param in params:
            if param in redirect_keys:
                for payload in REDIRECT_PAYLOADS:
                    test_url = self.mutate(target, param, payload)
                    try:
                        r = client.request('GET', test_url)
                        if r.status_code in [301, 302, 303, 307, 308] and payload in r.headers.get('Location', ''):
                            score = CVSSv3.score(c='L', i='L', a='N')
                            findings.append(Vulnerability(
                                title='Open Redirect',
                                description='User-controlled redirect target is accepted.',
                                severity=CVSSv3.severity(score),
                                cvss_score=score,
                                cwe='CWE-601',
                                owasp='A01:2021 Broken Access Control',
                                category='Redirect',
                                affected_target=context['target'],
                                endpoint=urlsplit(target).path or '/',
                                parameter=param,
                                poc=f'Redirected to attacker-controlled URL: {payload}',
                                remediation='Restrict redirects to relative paths or explicit allowlists.',
                                evidence=[Evidence(type='redirect', description='Untrusted redirect accepted', data={'location': r.headers.get('Location', '')})],
                                confidence=0.88,
                                tags=['redirect', 'phishing']
                            ))
                            break
                    except Exception:
                        continue
        return findings
