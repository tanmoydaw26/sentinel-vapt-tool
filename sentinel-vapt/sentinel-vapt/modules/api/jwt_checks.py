import base64
import json
import re
from modules.base import BaseModule
from core.models import Vulnerability, Evidence
from core.cvss import CVSSv3

class JWTChecks(BaseModule):
    name = 'jwt_checks'
    category = 'api'

    def run(self, context):
        client = context['client']
        findings = []
        try:
            r = client.request('GET', context['target'])
            auth = r.headers.get('Authorization', '') + ' ' + r.text[:5000]
            token_match = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+', auth)
            if token_match:
                token = token_match.group(0)
                header = token.split('.')[0] + '=='
                decoded = json.loads(base64.urlsafe_b64decode(header).decode(errors='ignore'))
                alg = decoded.get('alg', 'unknown')
                if alg.lower() == 'none':
                    score = CVSSv3.score(c='H', i='H', a='L')
                    findings.append(Vulnerability(
                        title='Weak JWT Configuration',
                        description='JWT uses insecure algorithm configuration.',
                        severity=CVSSv3.severity(score),
                        cvss_score=score,
                        cwe='CWE-347',
                        owasp='API2:2023 Broken Authentication',
                        category='Authentication',
                        affected_target=context['target'],
                        endpoint=context['target'],
                        poc='JWT header indicates alg=none.',
                        remediation='Enforce signed JWTs with strong algorithms and validate claims strictly.',
                        evidence=[Evidence(type='jwt', description='Insecure JWT algorithm', data={'alg': alg})],
                        confidence=0.92,
                        tags=['jwt', 'api', 'auth']
                    ))
        except Exception:
            pass
        return findings
