from urllib.parse import urlsplit, parse_qs
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3
from utils.helpers import SSRF_PAYLOADS

class SSRFModule(BaseModule):
    name = 'ssrf'
    category = 'web'

    def run(self, context):
        target = context['target']
        findings = []
        parts = urlsplit(target)
        params = parse_qs(parts.query)
        suspect_params = ['url', 'uri', 'dest', 'redirect', 'next', 'feed', 'image', 'link']
        for param in params:
            if param.lower() in suspect_params:
                score = CVSSv3.score(c='H', i='L', a='L')
                findings.append(Vulnerability(
                    title='Potential SSRF',
                    description='Parameter name and request pattern indicate possible server-side fetch behavior.',
                    severity=CVSSv3.severity(score),
                    cvss_score=score,
                    cwe='CWE-918',
                    owasp='A10:2021 Server-Side Request Forgery',
                    category='SSRF',
                    affected_target=context['target'],
                    endpoint=parts.path or '/',
                    parameter=param,
                    poc=f'Test with internal callback payloads such as {SSRF_PAYLOADS[0]} in safe mode only.',
                    remediation='Implement allowlists, network egress controls, and block internal metadata IP ranges.',
                    evidence=[Evidence(type='heuristic', description='SSRF-prone parameter discovered', data={'parameter': param})],
                    confidence=0.6,
                    tags=['ssrf', 'owasp-a10']
                ))
        return findings
