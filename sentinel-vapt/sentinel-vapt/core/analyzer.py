from collections import defaultdict

class SmartAnalyzer:
    def correlate(self, findings):
        categories = defaultdict(list)
        for f in findings:
            categories[f.category].append(f)

        titles = [f.title.lower() for f in findings]
        for f in findings:
            if 'Weak Authentication' in f.title and any('idor' in t or 'direct object reference' in t for t in titles):
                f.correlated_risk.append('Weak authentication combined with object-level access flaws can enable account takeover or unauthorized data access.')
            if 'Sensitive Data Exposure' in f.title and 'Missing Security Headers' in f.title:
                f.correlated_risk.append('Missing browser protections increases the exploitability of exposed sensitive content.')
            if 'Open Redirect' in f.title and any('jwt' in t or 'auth' in t for t in titles):
                f.correlated_risk.append('Open redirect may facilitate phishing in authentication workflows.')
        return findings

    def reduce_false_positives(self, findings):
        filtered = []
        for f in findings:
            if f.confidence >= 0.55:
                filtered.append(f)
        return filtered

    def dynamic_risk(self, findings):
        for f in findings:
            if len(f.evidence) >= 2:
                f.cvss_score = min(round(f.cvss_score + 0.3, 1), 10.0)
            if f.correlated_risk:
                f.cvss_score = min(round(f.cvss_score + 0.5, 1), 10.0)
        return findings

    def ai_explanation(self, finding):
        return (
            f"This issue matters because {finding.title.lower()} affects {finding.endpoint or finding.affected_target}. "
            f"An attacker could use it to compromise confidentiality, integrity, or availability depending on the business context. "
            f"The risk is amplified when combined with related weaknesses and reachable attack paths."
        )
