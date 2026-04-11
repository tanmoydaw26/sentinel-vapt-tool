import re
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3

class SensitiveDataExposureModule(BaseModule):
    name = 'sensitive_data'
    category = 'web'

    PATTERNS = {
        'email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+'
    }

    def run(self, context):
        client = context['client']
        findings = []
        try:
            r = client.request('GET', context['target'])
            matches = {}
            for name, pattern in self.PATTERNS.items():
                hit = re.findall(pattern, r.text)
                if hit:
                    matches[name] = len(hit)
            if matches:
                score = CVSSv3.score(c='H', i='L', a='N')
                findings.append(Vulnerability(
                    title='Sensitive Data Exposure',
                    description='Potential sensitive tokens or personal data appeared in server responses.',
                    severity=CVSSv3.severity(score),
                    cvss_score=score,
                    cwe='CWE-200',
                    owasp='A02:2021 Cryptographic Failures',
                    category='Data Exposure',
                    affected_target=context['target'],
                    endpoint=context['target'],
                    poc='Observed potentially sensitive patterns in response body.',
                    remediation='Do not expose secrets, tokens, or unnecessary personal data in responses.',
                    evidence=[Evidence(type='pattern_match', description='Sensitive patterns found', data=matches)],
                    confidence=0.76,
                    tags=['exposure', 'secrets', 'privacy']
                ))
        except Exception:
            pass
        return findings
